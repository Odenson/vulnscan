# vulnscan 🛡️

[![CI](https://github.com/Odenson/vulnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Odenson/vulnscan/actions/workflows/ci.yml)

Scan projects for **known vulnerabilities**, **vulnerable dependencies**, and
**insecure coding practices** — then review the findings in a static HTML
dashboard.

It's a *hybrid*: each scan type is both a standalone Python scanner (runnable
from the CLI / CI, no Claude required) **and** a Claude Code Skill, so you can
drive scans through Claude as well.

## Features

| Scanner | What it finds | Backed by |
|---|---|---|
| `dependency-audit` | Dependencies with known CVEs/advisories | [OSV.dev](https://osv.dev) API |
| `bad-practices` | Insecure patterns: `eval`/`exec`, `shell=True`, unsafe deserialization, disabled TLS verification, `innerHTML` XSS, weak hashing | regex SAST |
| `secrets` | Hardcoded AWS/GitHub/Slack/Google keys, private keys, JWTs, credential assignments | regex + entropy |

- **Zero runtime dependencies** — pure Python standard library.
- **Static dashboard** — scanners write JSON; `dashboard/index.html` renders it. No server.
- **CI-friendly** — `--fail-on high` exits non-zero to gate a pipeline.

## Project layout

```
vulnscan/
├── src/vulnscan/
│   ├── cli.py                 # `vulnscan scan <path>` entry point
│   ├── core/                  # models, registry, runner, JSON report writer
│   └── scanners/              # dependency_audit, bad_practices, secrets
├── skills/                    # one SKILL.md per scanner (Claude Code skills)
│   ├── dependency-audit/SKILL.md
│   ├── bad-practices/SKILL.md
│   └── secrets/SKILL.md
├── dashboard/                 # static HTML/CSS/JS dashboard
│   ├── index.html
│   └── data/                  # generated findings JSON (+ committed samples)
├── tests/
├── pyproject.toml
└── README.md
```

## Install

```bash
# from the project root
python -m pip install -e .
# or run without installing (uses src/ directly):
#   python -m vulnscan.cli ...  (after `pip install -e .`)
```

> Requires Python 3.9+.

## Usage

```bash
# Scan a project (runs every scanner, writes to dashboard/data/)
vulnscan scan ../some-project

# Run specific scanners only
vulnscan scan ../some-project --only dependency-audit secrets

# List available scanners
vulnscan list

# Gate CI: non-zero exit if any high+ findings
vulnscan scan ../some-project --fail-on high

# Also emit a standalone JSON file
vulnscan scan ../some-project --json report.json
```

If you haven't `pip install`ed, the same works via the module:

```bash
python -m vulnscan.cli scan ../some-project
```

## View the dashboard

After a scan, open the dashboard. Because it fetches JSON, serve it over HTTP
(opening the file directly is blocked by browser CORS rules):

```bash
cd dashboard
python -m http.server 8000
# then open http://localhost:8000
```

The dashboard shows aggregate totals, a sortable/filterable list of scanned
projects, and per-project findings with severity filters. It ships with sample
data so it renders before your first scan.

## Run via Claude Code (skills)

The `skills/` directory contains a `SKILL.md` for each scanner. Point Claude
Code at this project (or copy the skills into your skills directory) and ask,
e.g., *"run a dependency audit on ../some-project"* — the matching skill tells
Claude how to invoke the scanner and interpret results.

## Adding a scanner

1. Create `src/vulnscan/scanners/my_scanner.py` subclassing `Scanner`.
2. Register it in `src/vulnscan/scanners/__init__.py` (`ALL_SCANNERS`).
3. Add a `skills/my-scanner/SKILL.md` wrapper.

The CLI, registry, and dashboard pick it up automatically.

## Tests

```bash
python -m pip install -e ".[dev]"
pytest
```

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and PR:

1. **Tests** — `pytest` across Python 3.9, 3.11, and 3.13.
2. **Self-scan** (push to `main` only) — runs vulnscan against this repo,
   uploads the report as a build artifact, and commits the refreshed base
   report (`dashboard/data/vulnscan.json` + `index.json`) back to the repo so
   the dashboard always has live data to render.

The self-scan commit is tagged `[skip ci]` and the trigger ignores
`dashboard/data/**`, so the bot's own commit never re-triggers the workflow.

## Caveats

- `bad-practices` is regex-based triage — fast and dependency-free, but expect
  false positives. It does **not** replace Semgrep/CodeQL/Bandit.
- `dependency-audit` needs network access to reach OSV.dev.
- Only scan code you are authorized to scan.

## License

MIT — see [LICENSE](LICENSE).
