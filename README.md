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

# List scanned projects in the dashboard report
vulnscan projects

# Remove scanned project(s) from the report (hard delete; -y skips the prompt)
vulnscan remove some-project -y
```

### Removing projects from the dashboard

`vulnscan remove <name-or-slug>` permanently deletes a project's data file,
drops it from `index.json`, and regenerates the bundle. Use `vulnscan projects`
to see the available slugs.

The dashboard also has a **✕ button** on each project row. Because the page is
static, that button removes the project from the *current view* only and shows
the exact `vulnscan remove …` command (with a Copy button) to make it
permanent — reloading restores the row until you run the command.

If you haven't `pip install`ed, the same works via the module:

```bash
python -m vulnscan.cli scan ../some-project
```

## View the dashboard

Each scan writes a `dashboard/data/findings.js` bundle, so you can just **open
`dashboard/index.html` directly in your browser** (double-click it) — no server
required.

If you prefer to serve it over HTTP (e.g. to view the committed sample JSON on a
fresh clone, before running a scan), that also works:

```bash
cd dashboard
python -m http.server 8000
# then open http://localhost:8000
```

The dashboard shows aggregate totals, a filterable list of scanned projects, and
per-project findings with severity filters. It ships with sample data so it
renders before your first scan.

Each project row shows its path as a **📁 folder link**. Clicking it opens the
project folder in a new tab. Because browsers sandbox local file access, this
only works when the dashboard is opened directly via `file://` (double-clicking
`index.html`) — when the dashboard is served over `http://`, browsers block
`file://` navigation and the link won't open.

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
2. **Self-scan** — runs vulnscan against this repo and uploads the report as a
   build artifact (downloadable from the run). It is **not** committed back to
   the repo.

Real scan results are generated artifacts and are never committed. Only the
synthetic demo fixtures (`sample-web-app.json`, `internal-api.json`) and the
`index.json` listing them are tracked, so the dashboard renders out-of-the-box;
your own scans stay local (and `findings.js` is gitignored).

## Caveats

- `bad-practices` is regex-based triage — fast and dependency-free, but expect
  false positives. It does **not** replace Semgrep/CodeQL/Bandit.
- `dependency-audit` needs network access to reach OSV.dev.
- Only scan code you are authorized to scan.

## License

MIT — see [LICENSE](LICENSE).
