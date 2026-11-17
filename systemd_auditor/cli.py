"""Command line entry point.

Only reads files under the roots given by ``--root`` (repeatable); it never
invokes ``systemctl``, ``busctl`` or the service manager.
"""

from __future__ import annotations

import argparse
import json
import sys

from .audit import audit_unit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m systemd_auditor",
        description="Static systemd unit hardening auditor (no systemctl calls).",
    )
    parser.add_argument("unit", help="unit name, e.g. nginx.service or app@worker1.service")
    parser.add_argument(
        "--root",
        action="append",
        dest="roots",
        help="unit search root (repeatable, precedence in argument order); "
        "defaults to the compiled-in systemd search path",
    )
    parser.add_argument(
        "--path-prefix",
        default="",
        help="prefix prepended to analyzed binaries/config paths (staged trees)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = audit_unit(args.unit, search_roots=args.roots, path_prefix=args.path_prefix)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(report.to_text())
    return 1 if any(f.severity.value in ("high", "medium") for f in report.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
