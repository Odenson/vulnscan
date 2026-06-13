---
name: secrets
description: Scan a target project for hardcoded secrets and credentials committed to source - AWS keys, GitHub/Slack tokens, Google API keys, private keys, JWTs, and password/api_key assignments. Use when the user wants to find leaked secrets, check for committed credentials, or run a secrets scan on a codebase.
---

# Hardcoded Secrets Scan

Detect credentials and key material accidentally committed to source code.

## When to use
- Before pushing a repo public, or auditing one that already is.
- Investigating a possible credential leak.
- As part of a full scan (alongside `dependency-audit` and `bad-practices`).

## How to run

```bash
python -m vulnscan.cli scan <TARGET_PROJECT_PATH> --only secrets
```

Detects: AWS access keys, GitHub tokens, Slack tokens, Google API keys, PEM
private keys, JWTs, and high-entropy `password`/`api_key`/`secret` assignments.
Detected values are **masked** in the report — the dashboard JSON never stores
the full secret.

## Acting on findings
A confirmed secret is an emergency: **rotate it immediately**, then remove it
from source and load it from an environment variable or secret manager.
Removing it from the latest commit is not enough — it remains in git history
until purged.

## Implementation
Backed by `src/vulnscan/scanners/secrets.py`. Add detectors by appending to the
`RULES` list; the generic-assignment rule uses an entropy + placeholder filter
to cut false positives.
