"""Smoke tests for the scanners against a generated fixture project."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscan.core.runner import run_scan
from vulnscan.core.report import write_result
from vulnscan.scanners.bad_practices import BadPracticesScanner
from vulnscan.scanners.secrets import SecretsScanner
from vulnscan.core.models import Project


@pytest.fixture
def fixture_project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import subprocess, yaml, hashlib\n"
        "subprocess.run(cmd, shell=True)\n"
        "config = yaml.load(open('c.yml'))\n"
        "h = hashlib.md5(b'x').hexdigest()\n"
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\nrequests==2.19.0\n", encoding="utf-8")
    return tmp_path


def test_bad_practices_finds_patterns(fixture_project: Path):
    project = Project.from_path(fixture_project)
    findings = BadPracticesScanner().scan(project)
    ids = {f.vulnerability_id for f in findings}
    assert "py-shell-true" in ids
    assert "py-yaml-load" in ids
    assert "py-md5" in ids


def test_secrets_finds_aws_key(fixture_project: Path):
    project = Project.from_path(fixture_project)
    findings = SecretsScanner().scan(project)
    assert any(f.vulnerability_id == "aws-access-key" for f in findings)
    # The full key must never appear in the report.
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.description for f in findings)


def test_run_scan_offline_does_not_crash(fixture_project: Path):
    # dependency-audit may hit the network; run only offline scanners here.
    result = run_scan(str(fixture_project), ["bad-practices", "secrets"])
    assert result.summary()["total"] > 0
    assert "bad-practices" in result.scanners_run


def test_write_result_creates_index(fixture_project: Path, tmp_path: Path):
    result = run_scan(str(fixture_project), ["bad-practices", "secrets"])
    data_dir = tmp_path / "out"
    write_result(result, data_dir)
    index = json.loads((data_dir / "index.json").read_text(encoding="utf-8"))
    assert len(index["projects"]) == 1
    slug = index["projects"][0]["slug"]
    assert (data_dir / f"{slug}.json").exists()
