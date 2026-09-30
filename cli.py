import argparse
import json
from collections import Counter

from .scanner import scan
from .models import SEVERITIES


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secureconfig-audit",
        description="Audit application configuration for common security mistakes."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    command = sub.add_parser("scan", help="scan a file or directory")
    command.add_argument("target")
    command.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="output format"
    )
    command.add_argument(
        "--fail-on", choices=SEVERITIES, default=None,
        help="return exit code 1 when a finding at or above this severity exists"
    )
    return parser


def severity_rank(value):
    return SEVERITIES.index(value)


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        findings = scan(args.target)

        if args.format == "json":
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            for item in findings:
                print(f"{item.severity.upper():8} {item.file}:{item.line}  {item.message}")
            counts = Counter(f.severity for f in findings)
            print(f"\n{len(findings)} finding(s)")
            if counts:
                print("Summary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

        if args.fail_on and any(
            severity_rank(f.severity) >= severity_rank(args.fail_on)
            for f in findings
        ):
            return 1
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
