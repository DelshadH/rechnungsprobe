from __future__ import annotations

import argparse

from rechnungsprobe import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rechnungsprobe",
        description="Pre-release compatibility tester for XRechnung importers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("fuzz", help="Generate, validate, run, and reduce importer cases")
    subparsers.add_parser("replay", help="Replay a saved finding capsule")
    subparsers.add_parser("verify", help="Verify a result capsule and its invoice")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    parser.error(f"{args.command!r} is not available in this pre-release build")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
