"""Tests for the report writer and project removal."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscan.core.report import load_projects, remove_project, write_result
from vulnscan.core.runner import run_scan


@pytest.fixture
def populated_data_dir(tmp_path: Path) -> Path:
    """Scan two fixture projects into a scratch data dir; return the data dir."""
    data_dir = tmp_path / "data"
    for name in ("alpha", "beta"):
        proj = tmp_path / name
        proj.mkdir()
        (proj / "app.py").write_text(
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "subprocess.run(cmd, shell=True)\n",
            encoding="utf-8",
        )
        result = run_scan(str(proj), ["bad-practices", "secrets"])
        write_result(result, data_dir)
    return data_dir


def test_setup_has_two_projects(populated_data_dir: Path):
    slugs = {p["slug"] for p in load_projects(populated_data_dir)}
    assert slugs == {"alpha", "beta"}
    assert (populated_data_dir / "alpha.json").exists()
    assert (populated_data_dir / "findings.js").exists()


def test_remove_by_slug_hard_deletes(populated_data_dir: Path):
    removed = remove_project("alpha", populated_data_dir)
    assert removed == ["alpha"]
    # Data file gone, index entry gone.
    assert not (populated_data_dir / "alpha.json").exists()
    assert {p["slug"] for p in load_projects(populated_data_dir)} == {"beta"}
    # Bundle no longer references the removed project.
    bundle = (populated_data_dir / "findings.js").read_text(encoding="utf-8")
    assert "alpha" not in bundle
    assert "beta" in bundle


def test_remove_by_name_is_case_insensitive(populated_data_dir: Path):
    # run_scan names the project after the directory ("beta").
    removed = remove_project("BETA", populated_data_dir)
    assert removed == ["beta"]
    assert not (populated_data_dir / "beta.json").exists()


def test_remove_unknown_is_noop(populated_data_dir: Path):
    before = json.dumps(load_projects(populated_data_dir), sort_keys=True)
    removed = remove_project("does-not-exist", populated_data_dir)
    assert removed == []
    after = json.dumps(load_projects(populated_data_dir), sort_keys=True)
    assert before == after


def test_load_projects_missing_dir_returns_empty(tmp_path: Path):
    assert load_projects(tmp_path / "nope") == []
