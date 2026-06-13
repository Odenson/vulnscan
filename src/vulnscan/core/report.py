"""Persist scan results to the dashboard's data directory.

The dashboard reads three files:

* ``<data_dir>/index.json``   -> list of all scanned projects + summaries
* ``<data_dir>/<slug>.json``  -> full findings for one project
* ``<data_dir>/findings.js``  -> all projects + findings as a JS global

The JSON files are handy for CI artifacts and programmatic use. The
``findings.js`` bundle lets the dashboard work when opened directly from
disk (``file://``), where browsers block ``fetch()`` of local JSON.
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
    _write_bundle(data_dir)
    return project_file


def load_projects(data_dir: str | Path = DEFAULT_DATA_DIR) -> list[dict]:
    """Return the list of scanned-project entries from ``index.json`` (or [])."""
    index_file = Path(data_dir) / "index.json"
    if not index_file.exists():
        return []
    try:
        return json.loads(index_file.read_text(encoding="utf-8")).get("projects", [])
    except (json.JSONDecodeError, OSError):
        return []


def remove_project(target: str, data_dir: str | Path = DEFAULT_DATA_DIR) -> list[str]:
    """Hard-delete scanned project(s) matching ``target`` (by slug or name).

    Deletes each matched project's data file, drops it from ``index.json``, and
    regenerates the dashboard bundle. Returns the slugs that were removed (empty
    if nothing matched).
    """
    data_dir = Path(data_dir)
    projects = load_projects(data_dir)
    if not projects:
        return []

    target_slug = _slug(target)
    target_lower = target.lower()

    def matches(entry: dict) -> bool:
        return (
            entry.get("slug", "") == target_slug
            or entry.get("project", "").lower() == target_lower
        )

    removed = [e for e in projects if matches(e)]
    if not removed:
        return []

    for entry in removed:
        data_file = data_dir / entry.get("data_file", f"{entry.get('slug', '')}.json")
        try:
            data_file.unlink()
        except FileNotFoundError:
            pass

    kept = [e for e in projects if not matches(e)]
    _write_index(data_dir, kept)
    _write_bundle(data_dir)
    return [e.get("slug", "") for e in removed]


def _write_bundle(data_dir: Path) -> None:
    """Bundle every project's full result into a file:// friendly JS global."""
    index_file = data_dir / "index.json"
    if not index_file.exists():
        return
    try:
        index = json.loads(index_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return

    projects: list[dict] = []
    for entry in index.get("projects", []):
        pfile = data_dir / entry.get("data_file", "")
        if not pfile.exists():
            continue
        try:
            projects.append(json.loads(pfile.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue

    bundle = {"generated_at": index.get("generated_at"), "projects": projects}
    js = "window.VULNSCAN_DATA = " + json.dumps(bundle, indent=2) + ";\n"
    (data_dir / "findings.js").write_text(js, encoding="utf-8")


def _update_index(data_dir: Path, slug: str, payload: dict) -> None:
    projects = [p for p in load_projects(data_dir) if p.get("slug") != slug]
    projects.append({
        "slug": slug,
        "project": payload["project"],
        "project_path": payload["project_path"],
        "scanned_at": payload["scanned_at"],
        "summary": payload["summary"],
        "scanners_run": payload["scanners_run"],
        "data_file": f"{slug}.json",
    })
    _write_index(data_dir, projects, generated_at=payload["scanned_at"])


def _write_index(data_dir: Path, projects: list[dict], generated_at: str | None = None) -> None:
    """Write ``index.json`` with projects sorted newest-first.

    When ``generated_at`` is omitted (e.g. on removal), the existing index's
    timestamp is preserved.
    """
    index_file = data_dir / "index.json"
    if generated_at is None:
        if index_file.exists():
            try:
                generated_at = json.loads(index_file.read_text(encoding="utf-8")).get("generated_at")
            except (json.JSONDecodeError, OSError):
                generated_at = None

    projects = sorted(projects, key=lambda p: p.get("scanned_at", ""), reverse=True)
    index_file.write_text(
        json.dumps({"generated_at": generated_at, "projects": projects}, indent=2),
        encoding="utf-8",
    )
