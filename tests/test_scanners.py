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


# --- Dependency / virtual-env exclusion -------------------------------------

def test_virtualenv_is_excluded_by_pyvenv_cfg(tmp_path: Path):
    """A venv folder (any name) carrying pyvenv.cfg must be skipped whole."""
    (tmp_path / "app.py").write_text("eval('1')\n", encoding="utf-8")
    # A non-standard venv name that a fixed name-list would miss.
    venv = tmp_path / ".ven" / "Lib" / "site-packages" / "pkg"
    venv.mkdir(parents=True)
    (tmp_path / ".ven" / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    (venv / "rsa.py").write_text(
        "_MARKER = '-----BEGIN RSA PRIVATE KEY-----'\neval('x')\n", encoding="utf-8"
    )

    project = Project.from_path(tmp_path)
    files = {project.rel(p) for p in project.iter_files()}
    assert "app.py" in files
    assert not any("site-packages" in f or ".ven" in f for f in files)

    findings = run_scan(str(tmp_path), ["bad-practices", "secrets"]).findings
    # Only the real app.py eval should be flagged, nothing from the venv.
    assert all(".ven" not in (f.file or "") for f in findings)
    assert any(f.file == "app.py" for f in findings)


def test_site_packages_excluded_by_name(tmp_path: Path):
    """site-packages is skipped even without a pyvenv.cfg marker."""
    deep = tmp_path / "env2" / "lib" / "site-packages"
    deep.mkdir(parents=True)
    (deep / "x.py").write_text("eval('x')\n", encoding="utf-8")
    project = Project.from_path(tmp_path)
    assert not any("site-packages" in project.rel(p) for p in project.iter_files())


# --- Smarter .env messaging --------------------------------------------------

GOOGLE_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu"  # fake; AIza + 35 chars = 39


def test_dotenv_not_gitignored_stays_high(tmp_path: Path):
    (tmp_path / ".env").write_text(f"GOOGLE_API_KEY={GOOGLE_KEY}\n", encoding="utf-8")
    findings = SecretsScanner().scan(Project.from_path(tmp_path))
    env_findings = [f for f in findings if f.file == ".env"]
    assert env_findings, "expected a secret finding in .env"
    f = env_findings[0]
    assert f.severity == "high"  # base severity, not downgraded
    assert ".env file" in f.recommendation
    assert "NOT covered by .gitignore" in f.recommendation


def test_dotenv_gitignored_downgrades_to_medium(tmp_path: Path):
    (tmp_path / ".env").write_text(f"GOOGLE_API_KEY={GOOGLE_KEY}\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    findings = SecretsScanner().scan(Project.from_path(tmp_path))
    env_findings = [f for f in findings if f.file == ".env"]
    assert env_findings
    f = env_findings[0]
    assert f.severity == "medium"  # high downgraded one level when gitignored
    assert "covered by .gitignore (good)" in f.recommendation


def test_dotenv_gitignored_critical_only_drops_to_high(tmp_path: Path):
    # An AWS key (base 'critical') in a gitignored .env should land on 'high',
    # not be floored to medium — gitignored now != never committed.
    (tmp_path / ".env").write_text("AWS=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    findings = SecretsScanner().scan(Project.from_path(tmp_path))
    aws = [f for f in findings if f.vulnerability_id == "aws-access-key"]
    assert aws and aws[0].severity == "high"
