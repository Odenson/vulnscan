"""Orchestrates running scanners against a project."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from .models import Project, ScanResult
from .registry import resolve


def run_scan(path: str, scanner_names: list[str] | None = None) -> ScanResult:
    """Run the selected scanners against ``path`` and aggregate findings."""
    project = Project.from_path(path)
    if not project.root.exists():
        raise FileNotFoundError(f"Target path does not exist: {project.root}")

    scanners = resolve(scanner_names)
    findings = []
    errors: list[str] = []
    ran: list[str] = []

    start = time.perf_counter()
    for scanner in scanners:
        try:
            if not scanner.applies_to(project):
                continue
            ran.append(scanner.name)
            findings.extend(scanner.scan(project))
        except Exception as exc:  # one scanner failing must not kill the run
            errors.append(f"{scanner.name}: {exc}")
    duration = time.perf_counter() - start

    return ScanResult(
        project=project.name,
        project_path=str(project.root),
        scanned_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=duration,
        scanners_run=ran,
        findings=findings,
        errors=errors,
    )
