from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from rechnungsprobe.predicates import (
    CrashPredicate,
    DeclaredFieldLossPredicate,
    EvaluationContext,
    JsonPredicate,
    OutputValidityPredicate,
    PredicateEvaluation,
    TimeoutPredicate,
)
from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.reporting import strict_json
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import (
    ContainerTarget,
    LocalTarget,
    TargetResult,
    run_container_target,
    run_local_target,
)
from rechnungsprobe.validate import ValidationResult, validate_invoices

REPLAY_SCHEMA = "https://rechnungsprobe.dev/schemas/replay-v1"
_REPLAY_POLICY_CAPS = {
    "cpu_milliseconds": 120_000,
    "max_created_files": 1_024,
    "max_file_growth_bytes": 64 * 1024 * 1024,
    "max_input_bytes": 2 * 1024 * 1024,
    "max_memory_bytes": 1024 * 1024 * 1024,
    "max_output_bytes": 16 * 1024 * 1024,
    "max_processes": 32,
    "poll_milliseconds": 1_000,
    "timeout_milliseconds": 120_000,
}
ReplayTarget = LocalTarget | ContainerTarget
ReplayPredicate = (
    CrashPredicate
    | TimeoutPredicate
    | JsonPredicate
    | OutputValidityPredicate
    | DeclaredFieldLossPredicate
)


@dataclass(frozen=True, slots=True)
class ReplaySpecification:
    target: ReplayTarget
    predicate: ReplayPredicate
    policy: ProcessPolicy

    def __post_init__(self) -> None:
        if (
            isinstance(
                self.predicate,
                (OutputValidityPredicate, DeclaredFieldLossPredicate),
            )
            and self.target.output_file is None
        ):
            raise SecurityError("replay output predicate requires a target output file")


@dataclass(frozen=True, slots=True)
class ReplayExecution:
    target_result: TargetResult
    evaluation: PredicateEvaluation


def _milliseconds(value: float, field: str) -> int:
    if not math.isfinite(value) or value <= 0:
        raise SecurityError(f"replay {field} must be positive and finite")
    milliseconds = round(value * 1000)
    if abs(value - milliseconds / 1000) > 1e-12:
        raise SecurityError(f"replay {field} has finer than millisecond precision")
    return milliseconds


def _command(command: tuple[str, ...]) -> list[str]:
    if (
        not command
        or len(command) > 128
        or any(not argument or "\x00" in argument or len(argument) > 32_768 for argument in command)
    ):
        raise SecurityError("replay command is invalid or exceeds its limits")
    return list(command)


def _target_payload(target: ReplayTarget) -> dict[str, object]:
    payload: dict[str, object] = {
        "command": _command(target.command),
        "input_mode": target.input_mode,
        "kind": "container" if isinstance(target, ContainerTarget) else "local",
        "output_file": target.output_file,
    }
    if isinstance(target, ContainerTarget):
        payload["image"] = target.image
    return payload


def _predicate_payload(predicate: ReplayPredicate) -> dict[str, object]:
    if isinstance(predicate, JsonPredicate):
        return {
            "expected": predicate.expected,
            "kind": predicate.name,
            "pointer": predicate.pointer,
        }
    if isinstance(predicate, DeclaredFieldLossPredicate):
        return {"fields": list(predicate.fields), "kind": predicate.name}
    return {"kind": predicate.name}


def _policy_payload(policy: ProcessPolicy) -> dict[str, int]:
    payload = {
        "cpu_milliseconds": _milliseconds(policy.cpu_seconds, "CPU limit"),
        "max_created_files": policy.max_created_files,
        "max_file_growth_bytes": policy.max_file_growth_bytes,
        "max_input_bytes": policy.max_input_bytes,
        "max_memory_bytes": policy.max_memory_bytes,
        "max_output_bytes": policy.max_output_bytes,
        "max_processes": policy.max_processes,
        "poll_milliseconds": _milliseconds(
            policy.poll_interval_seconds,
            "poll interval",
        ),
        "timeout_milliseconds": _milliseconds(
            policy.timeout_seconds,
            "timeout",
        ),
    }
    nonnegative = {
        "max_created_files",
        "max_file_growth_bytes",
        "max_output_bytes",
    }
    if any(
        type(value) is not int
        or value < (0 if field in nonnegative else 1)
        or value > _REPLAY_POLICY_CAPS[field]
        for field, value in payload.items()
    ):
        raise SecurityError("replay resource policy exceeds its safe bounds")
    return payload


def replay_json(specification: ReplaySpecification) -> bytes:
    policy = specification.policy
    payload = {
        "policy": _policy_payload(policy),
        "predicate": _predicate_payload(specification.predicate),
        "schema": REPLAY_SCHEMA,
        "target": _target_payload(specification.target),
    }
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _integer(payload: object, field: str, *, positive: bool) -> int:
    if type(payload) is not int or (payload <= 0 if positive else payload < 0):
        raise SecurityError(f"replay {field} is invalid")
    return payload


def parse_replay_json(data: bytes) -> ReplaySpecification:
    payload = strict_json(data, max_bytes=128 * 1024)
    if not isinstance(payload, dict) or set(payload) != {
        "policy",
        "predicate",
        "schema",
        "target",
    }:
        raise SecurityError("replay specification has an invalid shape")
    if payload["schema"] != REPLAY_SCHEMA:
        raise SecurityError("replay specification schema is unsupported")

    target_payload = payload["target"]
    if not isinstance(target_payload, dict):
        raise SecurityError("replay target has an invalid shape")
    target_kind = target_payload.get("kind")
    expected_target_fields = (
        {
            "command",
            "image",
            "input_mode",
            "kind",
            "output_file",
        }
        if target_kind == "container"
        else {
            "command",
            "input_mode",
            "kind",
            "output_file",
        }
    )
    if set(target_payload) != expected_target_fields:
        raise SecurityError("replay target has an invalid shape")
    command_payload = target_payload["command"]
    if not isinstance(command_payload, list) or not all(
        isinstance(argument, str) for argument in command_payload
    ):
        raise SecurityError("replay target command has invalid types")
    command = tuple(_command(tuple(command_payload)))
    input_mode = target_payload["input_mode"]
    output_file = target_payload["output_file"]
    if input_mode not in {"stdin", "file"} or (
        output_file is not None and not isinstance(output_file, str)
    ):
        raise SecurityError("replay target is invalid")
    if target_kind == "local":
        target: ReplayTarget = LocalTarget(
            command=command,
            input_mode=input_mode,
            output_file=output_file,
        )
    elif target_kind == "container" and isinstance(target_payload["image"], str):
        target = ContainerTarget(
            image=target_payload["image"],
            command=command,
            input_mode=input_mode,
            output_file=output_file,
        )
    else:
        raise SecurityError("replay target is invalid")

    predicate_payload = payload["predicate"]
    if not isinstance(predicate_payload, dict):
        raise SecurityError("replay predicate is invalid or unsupported")
    predicate_kind = predicate_payload.get("kind")
    if predicate_payload == {"kind": "crash-or-nonzero"}:
        predicate: ReplayPredicate = CrashPredicate()
    elif predicate_payload == {"kind": "timeout"}:
        predicate = TimeoutPredicate()
    elif predicate_payload == {"kind": "output-invalid"}:
        predicate = OutputValidityPredicate()
    elif set(predicate_payload) == {"expected", "kind", "pointer"} and (
        predicate_kind == "stdout-json"
    ):
        pointer = predicate_payload["pointer"]
        expected = predicate_payload["expected"]
        if (
            not isinstance(pointer, str)
            or not (pointer == "" or pointer.startswith("/"))
            or len(pointer) > 1000
            or not (isinstance(expected, (str, int, bool)) or expected is None)
            or isinstance(expected, float)
        ):
            raise SecurityError("replay JSON predicate is invalid")
        predicate = JsonPredicate(pointer=pointer, expected=expected)
    elif set(predicate_payload) == {"fields", "kind"} and (predicate_kind == "declared-field-loss"):
        fields = predicate_payload["fields"]
        if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
            raise SecurityError("replay field-loss predicate is invalid")
        predicate = DeclaredFieldLossPredicate(tuple(fields))
    else:
        raise SecurityError("replay predicate is invalid or unsupported")

    policy_payload = payload["policy"]
    policy_fields = {
        "cpu_milliseconds",
        "max_created_files",
        "max_file_growth_bytes",
        "max_input_bytes",
        "max_memory_bytes",
        "max_output_bytes",
        "max_processes",
        "poll_milliseconds",
        "timeout_milliseconds",
    }
    if not isinstance(policy_payload, dict) or set(policy_payload) != policy_fields:
        raise SecurityError("replay resource policy has an invalid shape")
    policy = ProcessPolicy(
        timeout_seconds=_integer(
            policy_payload["timeout_milliseconds"],
            "timeout",
            positive=True,
        )
        / 1000,
        cpu_seconds=_integer(
            policy_payload["cpu_milliseconds"],
            "CPU limit",
            positive=True,
        )
        / 1000,
        max_memory_bytes=_integer(
            policy_payload["max_memory_bytes"],
            "memory limit",
            positive=True,
        ),
        max_processes=_integer(
            policy_payload["max_processes"],
            "process limit",
            positive=True,
        ),
        max_output_bytes=_integer(
            policy_payload["max_output_bytes"],
            "output limit",
            positive=False,
        ),
        max_input_bytes=_integer(
            policy_payload["max_input_bytes"],
            "input limit",
            positive=True,
        ),
        max_file_growth_bytes=_integer(
            policy_payload["max_file_growth_bytes"],
            "file growth limit",
            positive=False,
        ),
        max_created_files=_integer(
            policy_payload["max_created_files"],
            "created file limit",
            positive=False,
        ),
        poll_interval_seconds=_integer(
            policy_payload["poll_milliseconds"],
            "poll interval",
            positive=True,
        )
        / 1000,
    )
    _policy_payload(policy)
    return ReplaySpecification(
        target=target,
        predicate=predicate,
        policy=policy,
    )


def _validation_result(
    invoice_xml: bytes,
    *,
    workspace: Path,
    case_id: str,
) -> ValidationResult:
    results = validate_invoices({case_id: invoice_xml}, workspace=workspace)
    if set(results) != {case_id}:
        raise SecurityError("validator returned an unexpected result set")
    return results[case_id]


def execute_replay(
    specification: ReplaySpecification,
    invoice_xml: bytes,
    *,
    workspace: Path,
) -> ReplayExecution:
    """Revalidate a capsule invoice and execute its exact recorded target policy."""

    with TemporaryDirectory(prefix="rpv-") as temporary:
        validation_root = Path(temporary)
        input_validation = _validation_result(
            invoice_xml,
            workspace=validation_root / "input",
            case_id="input",
        )
        if not input_validation.valid:
            detail = "; ".join(input_validation.errors) or "official validation failed"
            raise SecurityError(f"capsule invoice is invalid under the pinned profile: {detail}")

        if isinstance(specification.target, ContainerTarget):
            target_result = run_container_target(
                specification.target,
                invoice_xml,
                workspace=workspace,
                policy=specification.policy,
            )
        else:
            target_result = run_local_target(
                specification.target,
                invoice_xml,
                workspace=workspace,
                policy=specification.policy,
            )

        output_validation = None
        if (
            isinstance(specification.predicate, OutputValidityPredicate)
            and target_result.output_xml is not None
        ):
            try:
                output_validation = _validation_result(
                    target_result.output_xml,
                    workspace=validation_root / "output",
                    case_id="output",
                )
            except SecurityError as error:
                output_validation = ValidationResult(
                    valid=False,
                    profile_id="xrechnung-ubl-3.0.2-2026-01-31",
                    exit_code=1,
                    errors=(str(error),),
                    report_sha256=None,
                )
        evaluation = specification.predicate.evaluate(
            target_result,
            EvaluationContext(
                input_xml=invoice_xml,
                output_validation=output_validation,
            ),
        )
        return ReplayExecution(
            target_result=target_result,
            evaluation=evaluation,
        )
