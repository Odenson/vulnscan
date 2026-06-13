---
name: bad-practices
description: Scan a target project's source code for insecure or risky coding patterns (eval/exec, shell=True, unsafe deserialization, disabled TLS verification, innerHTML XSS, weak hashing, etc.). Use when the user wants a static security/code-quality review, a "bad practices" scan, or SAST-style triage of a codebase.
---

# Insecure Coding Practices Scan

Flag risky patterns in source code that commonly lead to vulnerabilities
(injection, RCE, insecure deserialization, XSS, weak crypto, disabled TLS
verification).

## When to use
- The user wants a quick static-analysis pass over a codebase.
- Reviewing a new repo for obvious security anti-patterns before a deeper audit.
- As part of a full scan (alongside `dependency-audit` and `secrets`).

## How to run

```bash
python -m vulnscan.cli scan <TARGET_PROJECT_PATH> --only bad-practices
```

Scans common source files (`.py`, `.js/.ts`, `.java`, `.rb`, `.go`, `.php`,
`.cs`, `.c/.cpp`, `.sh`) and reports file:line for each match.

## Scope and limits
This is regex-based first-pass triage — fast and dependency-free, but **not**
a substitute for a full SAST tool (Semgrep, CodeQL, Bandit). Treat findings as
leads to verify, not confirmed vulnerabilities. Expect some false positives;
confirm each before reporting it as exploitable.

## Implementation
Backed by `src/vulnscan/scanners/bad_practices.py`. Add detections by appending
to the `RULES` list (id, severity, file suffixes, regex, title, recommendation).
