from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rechnungsprobe import __version__
from rechnungsprobe.campaign import run_campaign
from rechnungsprobe.capsule import verify_finding_capsule
from rechnungsprobe.predicates import (
    CrashPredicate,
    DeclaredFieldLossPredicate,
    JsonPredicate,
    OutputValidityPredicate,
    TimeoutPredicate,
)
from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2
from rechnungsprobe.replay import execute_replay
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
    fuzz.add_argument("--output-file")
    fuzz.add_argument("--json-pointer")
    fuzz.add_argument("--json-expected")
    fuzz.add_argument("--field", action="append", default=[])
    fuzz.add_argument("--reproductions", default=5, type=int)
    fuzz.add_argument("target_command", nargs=argparse.REMAINDER)
    replay = subparsers.add_parser("replay", help="Replay a saved finding capsule")
    replay.add_argument("capsule", type=Path)
    replay.add_argument("--workspace", type=Path)
    replay.add_argument(
        "--allow-local-target",
        action="store_true",
        help="Explicitly allow the capsule to execute a host command",
    )
    verify = subparsers.add_parser("verify", help="Verify a result capsule and its invoice")
    verify.add_argument("capsule", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
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
            if isinstance(verified.replay.target, LocalTarget) and not args.allow_local_target:
                raise SecurityError("local capsule targets require --allow-local-target")
            if (
                target_configuration_digest(verified.replay.target)
                != verified.record.target_digest
            ):
                raise SecurityError(
                    "replay target configuration does not match the capsule digest"
                )
            workspace = args.workspace or args.capsule.with_name(args.capsule.name + ".replay-work")
            execution = execute_replay(
                verified.replay,
                verified.invoice_xml,
                workspace=workspace,
            )
            if execution.target_result.target_digest != verified.record.target_digest:
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
        print(
            json.dumps(
                {
                    "case_id": verified.record.case_id,
                    "predicate": execution.evaluation.predicate,
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
                    "profile_id": verified.record.profile_id,
                    "status": "verified",
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
