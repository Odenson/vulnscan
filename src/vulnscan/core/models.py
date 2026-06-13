"""Shared data models for scanners and reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Optional


# Ordered worst -> least so we can sort and compute summaries.
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

VALID_SEVERITIES = set(SEVERITY_ORDER)


@dataclass
class Finding:
    """A single issue discovered by a scanner."""

    scanner: str
    severity: str  # one of VALID_SEVERITIES
    title: str
    description: str = ""
    file: Optional[str] = None  # path relative to the scanned project root
    line: Optional[int] = None
    package: Optional[str] = None
    version: Optional[str] = None
    vulnerability_id: Optional[str] = None  # e.g. CVE / GHSA / OSV id
    fixed_version: Optional[str] = None
    recommendation: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        sev = (self.severity or "info").lower()
        self.severity = sev if sev in VALID_SEVERITIES else "info"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Project:
    """The target being scanned, plus a few convenience helpers."""

    root: Path
    name: str

    @classmethod
    def from_path(cls, path: str | Path) -> "Project":
        root = Path(path).resolve()
        return cls(root=root, name=root.name)

    def rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root))
        except ValueError:
            return str(path)

    def iter_files(
        self,
        suffixes: Optional[Iterable[str]] = None,
        ignore_dirs: Iterable[str] = (
            ".git", "node_modules", "venv", ".venv", "__pycache__",
            "dist", "build", ".tox", ".mypy_cache", "vendor", "target",
        ),
    ) -> Iterable[Path]:
        ignore = {d.lower() for d in ignore_dirs}
        suffix_set = {s.lower() for s in suffixes} if suffixes else None
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            if any(part.lower() in ignore for part in path.parts):
                continue
            if suffix_set is not None and path.suffix.lower() not in suffix_set:
                continue
            yield path


@dataclass
class ScanResult:
    """Aggregated output of a full scan run for one project."""

    project: str
    project_path: str
    scanned_at: str
    duration_seconds: float
    scanners_run: list[str]
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] += 1
        counts["total"] = len(self.findings)
        return counts

    def to_dict(self) -> dict:
        return {
            "project": self.project,
            "project_path": self.project_path,
            "scanned_at": self.scanned_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "scanners_run": self.scanners_run,
            "summary": self.summary(),
            "errors": self.errors,
            "findings": [f.to_dict() for f in sorted(
                self.findings,
                key=lambda f: (SEVERITY_ORDER[f.severity], f.scanner, f.file or ""),
            )],
        }
