"""Detect dependencies with known vulnerabilities via the OSV.dev API.

Parses common manifest files, collects (ecosystem, name, version) tuples, and
batch-queries https://osv.dev. No API key required. Falls back gracefully when
the network is unavailable (emits an ``info`` finding instead of crashing).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from ..core.models import Finding, Project
from .base import Scanner

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

MANIFESTS = {
    "requirements.txt": "PyPI",
    "package.json": "npm",
    "Gemfile.lock": "RubyGems",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
}


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    deps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    deps = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            version = re.sub(r"^[\^~>=<\s]+", "", str(ver)).split(" ")[0]
            if re.match(r"^\d", version):
                deps.append((name, version))
    return deps


def _parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    deps = []
    for m in re.finditer(r"^\s{4}([a-zA-Z0-9._-]+) \(([0-9][^)]*)\)", text, re.M):
        deps.append((m.group(1), m.group(2)))
    return deps


def _parse_go_mod(text: str) -> list[tuple[str, str]]:
    deps = []
    for m in re.finditer(r"^\s*([^\s]+/[^\s]+)\s+v([0-9][^\s]*)", text, re.M):
        deps.append((m.group(1), "v" + m.group(2)))
    return deps


def _parse_cargo_lock(text: str) -> list[tuple[str, str]]:
    deps = []
    name = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name:
            deps.append((name, line.split("=", 1)[1].strip().strip('"')))
            name = None
    return deps


PARSERS = {
    "requirements.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "Gemfile.lock": _parse_gemfile_lock,
    "go.mod": _parse_go_mod,
    "Cargo.lock": _parse_cargo_lock,
}


class DependencyAuditScanner(Scanner):
    name = "dependency-audit"
    description = "Flags dependencies with known vulnerabilities using OSV.dev."

    def applies_to(self, project: Project) -> bool:
        return any(
            (project.root / m).exists() or any(project.iter_files([Path(m).suffix]))
            for m in MANIFESTS
        )

    def scan(self, project: Project) -> list[Finding]:
        queries: list[dict] = []
        meta: list[dict] = []
        for path in project.iter_files():
            if path.name not in PARSERS:
                continue
            ecosystem = MANIFESTS[path.name]
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pkg, version in PARSERS[path.name](text):
                queries.append({
                    "package": {"name": pkg, "ecosystem": ecosystem},
                    "version": version,
                })
                meta.append({
                    "package": pkg, "version": version,
                    "ecosystem": ecosystem, "file": project.rel(path),
                })

        if not queries:
            return []

        try:
            results = self._query_osv(queries)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return [Finding(
                scanner=self.name,
                severity="info",
                title="Dependency audit skipped (OSV unreachable)",
                description=(
                    f"Could not reach OSV.dev to check {len(queries)} dependencies: {exc}. "
                    "Re-run with network access to get known-vulnerability results."
                ),
            )]

        findings: list[Finding] = []
        for info, res in zip(meta, results):
            for vuln in (res or {}).get("vulns", []) or []:
                findings.append(self._to_finding(info, vuln.get("id", "")))
        return findings

    def _query_osv(self, queries: list[dict]) -> list[dict]:
        out: list[dict] = []
        # OSV recommends batching; 100 at a time is comfortable.
        for i in range(0, len(queries), 100):
            chunk = queries[i:i + 100]
            req = urllib.request.Request(
                OSV_BATCH_URL,
                data=json.dumps({"queries": chunk}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            out.extend(body.get("results", []))
        return out

    def _to_finding(self, info: dict, vuln_id: str) -> Finding:
        details = self._vuln_details(vuln_id)
        severity = _osv_severity(details)
        summary = details.get("summary") or details.get("details", "")[:200] or vuln_id
        fixed = _fixed_version(details, info["package"])
        refs = [r.get("url") for r in details.get("references", []) if r.get("url")]
        return Finding(
            scanner=self.name,
            severity=severity,
            title=f"{info['package']} {info['version']} - {vuln_id}",
            description=summary,
            file=info["file"],
            package=info["package"],
            version=info["version"],
            vulnerability_id=vuln_id,
            fixed_version=fixed,
            recommendation=(
                f"Upgrade {info['package']} to {fixed} or later." if fixed
                else f"Review {vuln_id} and upgrade {info['package']} to a patched release."
            ),
            references=refs[:5],
        )

    def _vuln_details(self, vuln_id: str) -> dict:
        if not vuln_id:
            return {}
        try:
            with urllib.request.urlopen(OSV_VULN_URL + vuln_id, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            return {}


def _osv_severity(details: dict) -> str:
    # Prefer an explicit database_specific severity, else map CVSS score.
    db = (details.get("database_specific") or {}).get("severity", "")
    if isinstance(db, str) and db.lower() in {"critical", "high", "medium", "moderate", "low"}:
        return "medium" if db.lower() == "moderate" else db.lower()
    for sev in details.get("severity", []) or []:
        score = sev.get("score", "")
        m = re.search(r"(\d+\.\d+)", str(score))
        if m:
            v = float(m.group(1))
            if v >= 9.0:
                return "critical"
            if v >= 7.0:
                return "high"
            if v >= 4.0:
                return "medium"
            return "low"
    return "high"  # known vuln with unknown severity -> treat seriously


def _fixed_version(details: dict, package: str) -> str | None:
    for affected in details.get("affected", []) or []:
        if affected.get("package", {}).get("name") != package:
            continue
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None
