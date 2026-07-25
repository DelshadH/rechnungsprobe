from __future__ import annotations

import importlib
import json

import pytest

from rechnungsprobe.predicates import (
    CrashPredicate,
    DeclaredFieldLossPredicate,
    JsonPredicate,
    OutputValidityPredicate,
    TimeoutPredicate,
)
from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.replay import ReplaySpecification, parse_replay_json, replay_json
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import ContainerTarget, LocalTarget


def test_replay_configuration_serializes_to_canonical_bounded_json() -> None:
    try:
        replay = importlib.import_module("rechnungsprobe.replay")
    except ModuleNotFoundError:
        pytest.fail("replay configuration support is missing")
    specification = replay.ReplaySpecification(
        target=LocalTarget(
            command=("python", "-c", "pass"),
            input_mode="stdin",
        ),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(),
    )

    encoded = replay.replay_json(specification)

    assert json.loads(encoded) == {
        "policy": {
            "cpu_milliseconds": 8000,
            "max_created_files": 256,
            "max_file_growth_bytes": 16777216,
            "max_input_bytes": 2097152,
            "max_memory_bytes": 536870912,
            "max_output_bytes": 1048576,
            "max_processes": 8,
            "poll_milliseconds": 10,
            "timeout_milliseconds": 10000,
        },
        "predicate": {"kind": "crash-or-nonzero"},
        "schema": "https://rechnungsprobe.dev/schemas/replay-v1",
        "target": {
            "command": ["python", "-c", "pass"],
            "input_mode": "stdin",
            "kind": "local",
            "output_file": None,
        },
    }
    assert (
        json.dumps(
            json.loads(encoded),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
        == encoded
    )


def test_replay_configuration_round_trips_through_strict_parser() -> None:
    replay = importlib.import_module("rechnungsprobe.replay")
    specification = replay.ReplaySpecification(
        target=LocalTarget(
            command=("python", "-c", "pass"),
            input_mode="stdin",
            output_file="roundtrip.xml",
        ),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(
            timeout_seconds=2.5,
            cpu_seconds=2.0,
            max_memory_bytes=128 * 1024 * 1024,
            max_processes=2,
            max_output_bytes=4096,
            max_input_bytes=8192,
            max_file_growth_bytes=16384,
            max_created_files=4,
            poll_interval_seconds=0.02,
        ),
    )

    assert replay.parse_replay_json(replay.replay_json(specification)) == specification


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_milliseconds", 120_001),
        ("cpu_milliseconds", 120_001),
        ("max_memory_bytes", 1024 * 1024 * 1024 + 1),
        ("max_processes", 33),
        ("max_output_bytes", 16 * 1024 * 1024 + 1),
        ("max_input_bytes", 2 * 1024 * 1024 + 1),
        ("max_file_growth_bytes", 64 * 1024 * 1024 + 1),
        ("max_created_files", 1025),
        ("poll_milliseconds", 1001),
    ],
)
def test_replay_parser_rejects_resource_policies_above_safe_caps(
    field: str,
    value: int,
) -> None:
    payload = json.loads(
        replay_json(
            ReplaySpecification(
                target=LocalTarget(command=("importer",), input_mode="stdin"),
                predicate=CrashPredicate(),
                policy=ProcessPolicy(),
            )
        )
    )
    payload["policy"][field] = value
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    with pytest.raises(SecurityError, match="resource policy"):
        parse_replay_json(encoded)


def test_replay_serializer_rejects_resource_policies_above_safe_caps() -> None:
    specification = ReplaySpecification(
        target=LocalTarget(command=("importer",), input_mode="stdin"),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(timeout_seconds=120.001),
    )

    with pytest.raises(SecurityError, match="resource policy"):
        replay_json(specification)


@pytest.mark.parametrize(
    ("specification", "predicate_payload", "target_kind"),
    [
        (
            ReplaySpecification(
                target=LocalTarget(command=("importer",), input_mode="stdin"),
                predicate=TimeoutPredicate(),
                policy=ProcessPolicy(),
            ),
            {"kind": "timeout"},
            "local",
        ),
        (
            ReplaySpecification(
                target=LocalTarget(command=("importer",), input_mode="stdin"),
                predicate=JsonPredicate(pointer="/accepted", expected=True),
                policy=ProcessPolicy(),
            ),
            {"expected": True, "kind": "stdout-json", "pointer": "/accepted"},
            "local",
        ),
        (
            ReplaySpecification(
                target=LocalTarget(
                    command=("importer",),
                    input_mode="file",
                    output_file="roundtrip.xml",
                ),
                predicate=OutputValidityPredicate(),
                policy=ProcessPolicy(),
            ),
            {"kind": "output-invalid"},
            "local",
        ),
        (
            ReplaySpecification(
                target=LocalTarget(
                    command=("importer",),
                    input_mode="file",
                    output_file="roundtrip.xml",
                ),
                predicate=DeclaredFieldLossPredicate(("buyer_reference", "lines.description")),
                policy=ProcessPolicy(),
            ),
            {
                "fields": ["buyer_reference", "lines.description"],
                "kind": "declared-field-loss",
            },
            "local",
        ),
        (
            ReplaySpecification(
                target=ContainerTarget(
                    image="example/importer@sha256:" + "f" * 64,
                    command=("import", "/input/invoice.xml"),
                    input_mode="file",
                ),
                predicate=CrashPredicate(),
                policy=ProcessPolicy(),
            ),
            {"kind": "crash-or-nonzero"},
            "container",
        ),
    ],
)
def test_replay_configuration_supports_every_released_variant(
    specification: ReplaySpecification,
    predicate_payload: dict[str, object],
    target_kind: str,
) -> None:
    encoded = replay_json(specification)
    payload = json.loads(encoded)

    assert payload["predicate"] == predicate_payload
    assert payload["target"]["kind"] == target_kind
    assert parse_replay_json(encoded) == specification
