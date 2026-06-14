"""Command-line entry point for vulnscan.

Examples
--------
    vulnscan scan ../some-project
    vulnscan scan ../some-project --only dependency-audit secrets
    vulnscan scan ../some-project --data-dir dashboard/data --json out.json
    vulnscan list
    vulnscan projects
    vulnscan remove some-project -y
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.models import SEVERITY_ORDER
from .core.registry import available_scanners
from .core.report import DEFAULT_DATA_DIR, load_projects, remove_project, write_result
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


def _cmd_projects(args: argparse.Namespace) -> int:
    projects = load_projects(args.data_dir)
    if not projects:
        print(f"No scanned projects in {Path(args.data_dir) / 'index.json'}.")
        return 0
    print(f"Scanned projects ({len(projects)}):\n")
    print(f"  {'SLUG':<22} {'TOTAL':>5}  {'SCANNED':<26} PROJECT")
    for p in projects:
        total = (p.get("summary") or {}).get("total", 0)
        print(f"  {p.get('slug', ''):<22} {total:>5}  "
              f"{p.get('scanned_at', ''):<26} {p.get('project', '')}")
    return 0


def _cmd_remove(args: argparse.Namespace) -> int:
    projects = load_projects(args.data_dir)
    by_key = {p.get("slug", ""): p for p in projects}
    by_key.update({p.get("project", "").lower(): p for p in projects})

    removed_any = False
    not_found = []
    for target in args.targets:
        entry = by_key.get(target) or by_key.get(target.lower())
        if entry is None:
            not_found.append(target)
            continue
        slug = entry.get("slug", target)
        if not args.yes and sys.stdin.isatty():
            data_file = entry.get("data_file", f"{slug}.json")
            answer = input(f"Remove '{slug}' and delete {data_file}? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print(f"skipped: {slug}")
                continue
        removed = remove_project(target, args.data_dir)
        for s in removed:
            print(f"removed: {s}")
            removed_any = True

    for target in not_found:
        print(f"not found: {target}", file=sys.stderr)

    if not_found and not removed_any:
        return 1
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

    p_projects = sub.add_parser("projects", help="List scanned projects in the report.")
    p_projects.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR),
                            help="Dashboard data directory (default: dashboard/data).")
    p_projects.set_defaults(func=_cmd_projects)

    p_remove = sub.add_parser(
        "remove",
        help="Remove scanned project(s) from the report (hard delete).",
    )
    p_remove.add_argument("targets", nargs="+", metavar="NAME_OR_SLUG",
                          help="Project name(s) or slug(s) to remove.")
    p_remove.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR),
                          help="Dashboard data directory (default: dashboard/data).")
    p_remove.add_argument("-y", "--yes", action="store_true",
                          help="Skip the confirmation prompt.")
    p_remove.set_defaults(func=_cmd_remove)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
