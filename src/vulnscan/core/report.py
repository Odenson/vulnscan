"""Persist scan results to the dashboard's data directory.

The dashboard reads two files:

* ``<data_dir>/index.json``   -> list of all scanned projects + summaries
* ``<data_dir>/<slug>.json``  -> full findings for one project

This keeps the dashboard a pure static site: scanners write JSON, the
browser fetches and renders it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import ScanResult

DEFAULT_DATA_DIR = Path("dashboard/data")


def _slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name).strip("-").lower()
    return s or "project"


def write_result(result: ScanResult, data_dir: str | Path = DEFAULT_DATA_DIR) -> Path:
    """Write one project's findings and update the dashboard index."""
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    slug = _slug(result.project)
    project_file = data_dir / f"{slug}.json"
    payload = result.to_dict()
    payload["slug"] = slug
    project_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    _update_index(data_dir, slug, payload)
    return project_file


def _update_index(data_dir: Path, slug: str, payload: dict) -> None:
    index_file = data_dir / "index.json"
    projects: list[dict] = []
    if index_file.exists():
        try:
            projects = json.loads(index_file.read_text(encoding="utf-8")).get("projects", [])
        except (json.JSONDecodeError, OSError):
            projects = []

    entry = {
        "slug": slug,
        "project": payload["project"],
        "project_path": payload["project_path"],
        "scanned_at": payload["scanned_at"],
        "summary": payload["summary"],
        "scanners_run": payload["scanners_run"],
        "data_file": f"{slug}.json",
    }

    projects = [p for p in projects if p.get("slug") != slug]
    projects.append(entry)
    projects.sort(key=lambda p: p.get("scanned_at", ""), reverse=True)

    index_file.write_text(
        json.dumps({"generated_at": payload["scanned_at"], "projects": projects}, indent=2),
        encoding="utf-8",
    )
