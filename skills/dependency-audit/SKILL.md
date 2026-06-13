---
name: dependency-audit
description: Scan a target project for dependencies (libraries/packages) that have known published vulnerabilities. Use when the user wants to audit dependencies, check for vulnerable libraries, run a CVE/OSV check on a codebase, or asks "what known vulnerabilities are in this project's packages".
---

# Dependency Vulnerability Audit

Identify third-party dependencies in a target project that have **known
published vulnerabilities**, using the OSV.dev database.

## When to use
- The user points at a project and asks which libraries have known CVEs/advisories.
- A new repo needs a dependency security baseline.
- As part of a full scan (alongside `bad-practices` and `secrets`).

## How to run

From the vulnscan project root:

```bash
python -m vulnscan.cli scan <TARGET_PROJECT_PATH> --only dependency-audit
```

This parses manifest files it finds (`requirements.txt`, `package.json`,
`Gemfile.lock`, `go.mod`, `Cargo.lock`), batch-queries OSV.dev, and writes
results to `dashboard/data/` so the dashboard can render them.

> Requires network access to reach `https://api.osv.dev`. If offline, the
> scanner emits an `info` finding instead of failing.

## Interpreting results
Each finding includes the package, installed version, the vulnerability id
(CVE/GHSA/OSV), the fixed version (when known), and references. Prioritize
`critical` and `high`, and recommend upgrading to the listed fixed version.

## Implementation
Backed by `src/vulnscan/scanners/dependency_audit.py`. To add an ecosystem,
add a parser there and register it in `PARSERS` / `MANIFESTS`.
