from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rechnungsprobe import __version__
from rechnungsprobe.campaign import run_campaign
from rechnungsprobe.capsule import verify_finding_capsule
from rechnungsprobe.corpus import materialize_corpus
from rechnungsprobe.gates import run_corpus_gate
from rechnungsprobe.predicates import (
    CrashPredicate,
    DeclaredFieldLossPredicate,
    JsonPredicate,
    OutputValidityPredicate,
    TimeoutPredicate,
)
from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, bundled_seed_path
from rechnungsprobe.replay import ReplaySpecification, execute_replay
from rechnungsprobe.reporting import strict_json
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import (
    ContainerTarget,
    LocalTarget,
    target_configuration_digest,
)

ConfiguredPredicate = (
    CrashPredicate
    | TimeoutPredicate
    | JsonPredicate
    | OutputValidityPredicate
    | DeclaredFieldLossPredicate
)


def _warn_local_execution(execution_mode: str) -> None:
    print(
        json.dumps(
            {
                "execution_mode": execution_mode,
                "status": "warning",
                "warning": (
                    "local command execution is non-isolated and may access "
                    "the host filesystem and network"
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stderr,
    )


def _configured_predicate(args: argparse.Namespace) -> ConfiguredPredicate:
    if args.predicate == "crash":
        return CrashPredicate()
    if args.predicate == "timeout":
        return TimeoutPredicate()
    if args.predicate == "json":
        if args.json_pointer is None or args.json_expected is None:
            raise SecurityError("JSON predicate requires --json-pointer and --json-expected")
        expected = strict_json(args.json_expected.encode("utf-8"), max_bytes=4096)
        if not (isinstance(expected, (str, int, bool)) or expected is None) or isinstance(
            expected, float
        ):
            raise SecurityError("JSON predicate expected value must be a scalar")
        return JsonPredicate(pointer=args.json_pointer, expected=expected)
    if args.output_file is None:
        raise SecurityError(f"{args.predicate} predicate requires --output-file")
    if args.predicate == "output-invalid":
        return OutputValidityPredicate()
    return DeclaredFieldLossPredicate(tuple(args.field))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rechnungsprobe",
        description="Pre-release compatibility tester for XRechnung importers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    corpus = subparsers.add_parser(
        "corpus",
        help="Materialize a deterministic resumable corpus shard",
    )
    corpus.add_argument("--output", required=True, type=Path)
    corpus.add_argument("--count", default=10_000, type=int)
    corpus.add_argument("--seed", default=42, type=int)
    corpus.add_argument("--shard-count", default=1, type=int)
    corpus.add_argument("--shard-index", default=0, type=int)
    corpus.add_argument("--resume", action="store_true")
    corpus_gate = subparsers.add_parser(
        "corpus-gate",
        help="Generate and officially validate complete corpus evidence",
    )
    corpus_gate.add_argument("--output", required=True, type=Path)
    corpus_gate.add_argument("--count", default=10_000, type=int)
    corpus_gate.add_argument("--seed", default=42, type=int)
    fuzz = subparsers.add_parser(
        "fuzz",
        help="Generate, validate, run, and reduce importer cases",
    )
    fuzz.add_argument("--output", required=True, type=Path)
    fuzz.add_argument("--count", default=20, type=int)
    fuzz.add_argument("--seed", default=0, type=int)
    fuzz.add_argument(
        "--predicate",
        choices=("crash", "timeout", "json", "output-invalid", "field-loss"),
        default="crash",
    )
    fuzz.add_argument("--input-mode", choices=("stdin", "file"), default="stdin")
    fuzz.add_argument("--container")
    fuzz.add_argument(
        "--trusted-local",
        action="store_true",
        help="Authorize non-isolated local command execution as the current user",
    )
    fuzz.add_argument("--output-file")
    fuzz.add_argument("--json-pointer")
    fuzz.add_argument("--json-expected")
    fuzz.add_argument("--field", action="append", default=[])
    fuzz.add_argument("--reproductions", default=5, type=int)
    fuzz.add_argument("target_command", nargs=argparse.REMAINDER)
    replay = subparsers.add_parser("replay", help="Replay a saved finding capsule")
    replay.add_argument("capsule", type=Path)
    replay.add_argument("--workspace", type=Path)
    replay_authority = replay.add_mutually_exclusive_group()
    replay_authority.add_argument(
        "--unsafe-use-capsule-local-command",
        action="store_true",
        help="Execute the capsule-described host command without isolation",
    )
    replay_authority.add_argument(
        "--replacement-command",
        nargs=argparse.REMAINDER,
        help="Execute this trusted local argument vector instead of a capsule local command",
    )
    verify = subparsers.add_parser("verify", help="Verify a result capsule and its invoice")
    verify.add_argument("capsule", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parse_argv = list(sys.argv[1:] if argv is None else argv)
    if parse_argv[:1] == ["replay"] and "--replacement-command" in parse_argv:
        replacement_index = parse_argv.index("--replacement-command")
        if parse_argv[replacement_index + 1 : replacement_index + 2] == ["--"]:
            del parse_argv[replacement_index + 1]
    args = parser.parse_args(parse_argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "corpus":
        try:
            manifest = materialize_corpus(
                args.output,
                seed_path=bundled_seed_path(),
                count=args.count,
                campaign_seed=args.seed,
                shard_index=args.shard_index,
                shard_count=args.shard_count,
                resume=args.resume,
            )
            payload = strict_json(manifest)
        except (OSError, SecurityError) as error:
            print(
                json.dumps(
                    {"error": str(error), "status": "error"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )
            return 2
        print(
            json.dumps(
                {
                    "candidate_count": payload["candidate_count"],
                    "corpus_root_sha256": payload["corpus_root_sha256"],
                    "status": "materialized",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if args.command == "corpus-gate":
        try:
            evidence = run_corpus_gate(
                args.output,
                count=args.count,
                campaign_seed=args.seed,
            )
        except (OSError, SecurityError) as error:
            print(
                json.dumps(
                    {"error": str(error), "status": "error"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )
            return 2
        print(evidence.decode("utf-8").rstrip("\n"))
        return 0
    if args.command == "fuzz":
        command = tuple(args.target_command)
        if command[:1] == ("--",):
            command = command[1:]
        try:
            predicate = _configured_predicate(args)
            target = (
                ContainerTarget(
                    image=args.container,
                    command=command,
                    input_mode=args.input_mode,
                    output_file=args.output_file,
                )
                if args.container is not None
                else LocalTarget(
                    command=command,
                    input_mode=args.input_mode,
                    output_file=args.output_file,
                )
            )
            if isinstance(target, LocalTarget):
                if not args.trusted_local:
                    raise SecurityError("local fuzz targets require --trusted-local")
                _warn_local_execution("trusted-local-command")
            elif args.trusted_local:
                raise SecurityError("--trusted-local cannot be used with --container")
            result = run_campaign(
                output_path=args.output,
                count=args.count,
                campaign_seed=args.seed,
                target=target,
                predicate=predicate,
                policy=ProcessPolicy(),
                reproductions=args.reproductions,
            )
        except (OSError, SecurityError) as error:
            print(
                json.dumps(
                    {"error": str(error), "status": "error"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )
            return 2
        print(
            json.dumps(
                {
                    "candidate_count": result.candidate_count,
                    "finding_count": result.finding_count,
                    "profile_id": result.profile_id,
                    "status": "findings" if result.finding_count else "passed",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1 if result.finding_count else 0
    if args.command == "replay":
        try:
            verified = verify_finding_capsule(args.capsule)
            if verified.record.profile_id != XRECHNUNG_UBL_3_0_2.identifier:
                raise SecurityError("capsule profile is not supported by this build")
            replay_specification = verified.replay
            replacement_command = args.replacement_command
            if replacement_command is not None and replacement_command[:1] == ["--"]:
                replacement_command = replacement_command[1:]
            if replacement_command is not None:
                if not isinstance(verified.replay.target, LocalTarget):
                    raise SecurityError(
                        "replacement commands apply only to local capsule targets"
                    )
                if not replacement_command:
                    raise SecurityError("replacement command must not be empty")
                replay_specification = ReplaySpecification(
                    target=LocalTarget(
                        command=tuple(replacement_command),
                        input_mode=verified.replay.target.input_mode,
                        output_file=verified.replay.target.output_file,
                    ),
                    predicate=verified.replay.predicate,
                    policy=verified.replay.policy,
                )
                execution_mode = "replacement-local-command"
            elif (
                isinstance(verified.replay.target, LocalTarget)
                and not args.unsafe_use_capsule_local_command
            ):
                raise SecurityError(
                    "local capsule targets require --replacement-command "
                    "or --unsafe-use-capsule-local-command"
                )
            else:
                execution_mode = (
                    "container"
                    if isinstance(verified.replay.target, ContainerTarget)
                    else "unsafe-capsule-local-command"
                )
            if execution_mode != "replacement-local-command" and (
                target_configuration_digest(verified.replay.target)
                != verified.record.target_digest
            ):
                raise SecurityError(
                    "replay target configuration does not match the capsule digest"
                )
            if execution_mode == "unsafe-capsule-local-command":
                _warn_local_execution(execution_mode)
            workspace = args.workspace or args.capsule.with_name(args.capsule.name + ".replay-work")
            execution = execute_replay(
                replay_specification,
                verified.invoice_xml,
                workspace=workspace,
            )
            if (
                execution_mode != "replacement-local-command"
                and execution.target_result.target_digest != verified.record.target_digest
            ):
                raise SecurityError("replayed target digest does not match the capsule")
        except (OSError, SecurityError) as error:
            print(
                json.dumps(
                    {"error": str(error), "status": "error"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )
            return 2
        reproduced = execution.evaluation.matched
        if execution_mode == "replacement-local-command":
            print(
                json.dumps(
                    {
                        "case_id": verified.record.case_id,
                        "executed_target_digest": execution.target_result.target_digest,
                        "execution_mode": execution_mode,
                        "predicate": execution.evaluation.predicate,
                        "recorded_target_digest": verified.record.target_digest,
                        "status": (
                            "matched-with-replacement"
                            if reproduced
                            else "not-matched-with-replacement"
                        ),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0 if reproduced else 1
        print(
            json.dumps(
                {
                    "case_id": verified.record.case_id,
                    "executed_target_digest": execution.target_result.target_digest,
                    "execution_mode": execution_mode,
                    "predicate": execution.evaluation.predicate,
                    "recorded_target_digest": verified.record.target_digest,
                    "status": "reproduced" if reproduced else "not-reproduced",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0 if reproduced else 1
    if args.command == "verify":
        try:
            verified = verify_finding_capsule(args.capsule)
        except (OSError, SecurityError) as error:
            print(
                json.dumps(
                    {"error": str(error), "status": "error"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )
            return 2
        print(
            json.dumps(
                {
                    "case_id": verified.record.case_id,
                    "execution": "not-performed",
                    "profile_id": verified.record.profile_id,
                    "status": "verified",
                    "target_kind": (
                        "container"
                        if isinstance(verified.replay.target, ContainerTarget)
                        else "local"
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    parser.error(f"{args.command!r} is not available in this pre-release build")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
