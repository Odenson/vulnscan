"""Command-line entry point for vulnscan.

Examples
--------
    vulnscan scan ../some-project
    vulnscan scan ../some-project --only dependency-audit secrets
    vulnscan scan ../some-project --data-dir dashboard/data --json out.json
    vulnscan list
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.models import SEVERITY_ORDER
from .core.registry import available_scanners
from .core.report import DEFAULT_DATA_DIR, write_result
from .core.runner import run_scan

# Exit non-zero when findings at/above this severity exist (CI gate).
_SEV_NAMES = list(SEVERITY_ORDER)

COLORS = {
    "critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[96m", "info": "\033[90m", "reset": "\033[0m",
}


def _color(sev: str, text: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS.get(sev, '')}{text}{COLORS['reset']}"


def _cmd_list(_: argparse.Namespace) -> int:
    print("Available scanners:\n")
    for name, cls in sorted(available_scanners().items()):
        print(f"  {name:<18} {cls.description}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    use_color = sys.stdout.isatty() and not args.no_color
    try:
        result = run_scan(args.path, args.only)
    except (FileNotFoundError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = result.summary()
    print(f"\nScanned: {result.project}  ({result.project_path})")
    print(f"Scanners: {', '.join(result.scanners_run) or 'none'}")
    print(f"Duration: {result.duration_seconds:.2f}s\n")

    for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER[f.severity]):
        loc = f.file or "-"
        if f.line:
            loc += f":{f.line}"
        tag = _color(f.severity, f"[{f.severity.upper():^8}]", use_color)
        print(f"{tag} {f.title}")
        print(f"           {loc}  ({f.scanner})")
        if f.recommendation:
            print(f"           -> {f.recommendation}")
    if not result.findings:
        print("No findings. ✔")

    print("\nSummary: " + "  ".join(
        f"{s}={summary[s]}" for s in _SEV_NAMES if summary[s]
    ) + f"   total={summary['total']}")

    if result.errors:
        print("\nScanner errors:")
        for e in result.errors:
            print(f"  - {e}")

    if not args.no_report:
        out = write_result(result, args.data_dir)
        print(f"\nReport written: {out}")
        print(f"Index updated:  {Path(args.data_dir) / 'index.json'}")

    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON written:   {args.json}")

    # CI gate
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= threshold for f in result.findings):
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Scan a project for known vulnerabilities and bad practices.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a target project directory.")
    p_scan.add_argument("path", help="Path to the project to scan.")
    p_scan.add_argument("--only", nargs="+", metavar="SCANNER",
                        help="Run only these scanners (default: all).")
    p_scan.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR),
                        help="Dashboard data directory (default: dashboard/data).")
    p_scan.add_argument("--json", metavar="FILE",
                        help="Also write the full result to this JSON file.")
    p_scan.add_argument("--no-report", action="store_true",
                        help="Do not write to the dashboard data directory.")
    p_scan.add_argument("--no-color", action="store_true", help="Disable colored output.")
    p_scan.add_argument("--fail-on", choices=_SEV_NAMES,
                        help="Exit non-zero if findings at/above this severity exist.")
    p_scan.set_defaults(func=_cmd_scan)

    p_list = sub.add_parser("list", help="List available scanners.")
    p_list.set_defaults(func=_cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
