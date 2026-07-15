# sentinel-scan

> A CLI that scans a repository for hardcoded secrets and known-vulnerable dependencies, and outputs a scored report — table, JSON, or Markdown.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/IamVanshKhanna/sentinel-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/IamVanshKhanna/sentinel-scan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

---

## Table of Contents

- [What It Does](#what-it-does)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [How Detection Works](#how-detection-works)
- [Repository Structure](#repository-structure)
- [Skills This Project Shows](#skills-this-project-shows)
- [License](#license)

---

## What It Does

1. **Secrets detection** — regex patterns for AWS keys, GitHub tokens, private key headers, Slack tokens, generic `api_key=`/`password=`-style assignments, plus a Shannon-entropy check on quoted strings to catch high-randomness values the regex list misses.
2. **Dependency vulnerability check** — parses `requirements.txt` and `package.json`, queries [OSV.dev](https://osv.dev) (Google's open-source vulnerability database, free, no API key) for known CVEs per package/version.
3. **Scored report** — every finding gets a severity (critical/high/medium/low); a total risk score is computed from the weighted sum.

Built to understand the technique, not to replace gitleaks or truffleHog — those are maintained, team-backed tools with curated ruleset libraries and (in truffleHog's case) live credential verification this doesn't attempt. This is a small, from-scratch implementation of the same core idea (regex + entropy detection, dependency CVE lookup) applied to my own repos before they went public, kept intentionally readable end to end.

---

## Quick Start

```bash
git clone https://github.com/IamVanshKhanna/sentinel-scan.git
cd sentinel-scan
pip install -e ".[dev]"

sentinel-scan .
```

## Usage

```bash
sentinel-scan /path/to/repo                 # table output
sentinel-scan /path/to/repo --json          # machine-readable
sentinel-scan /path/to/repo --markdown      # for a PR comment or report
sentinel-scan /path/to/repo --no-deps       # secrets only, skip network call
sentinel-scan /path/to/repo --fail-on high  # exit 1 if a high/critical finding exists — CI-friendly
```

---

## How Detection Works

**Secrets** — a small set of high-confidence patterns (not a giant unmaintained regex list) plus entropy scoring. Every detector is unit-tested against planted fake secrets in [`tests/fixtures/`](tests/fixtures/) — fake by construction (correct format, not live credentials), so the test suite doesn't itself leak anything or trip other scanners.

**Dependencies** — `requirements.txt`/`package.json` are parsed into `(name, version, ecosystem)` tuples and sent to OSV.dev's batch query API in one request. Network calls are mocked in tests (via `responses`) so the suite runs fully offline and deterministically.

**Design choice:** OSV.dev over a bundled static vulnerability database — real, continuously updated data instead of a snapshot that goes stale the day it ships.

---

## Repository Structure

```
sentinel-scan/
+-- sentinel_scan/
|   +-- cli.py         # argparse entrypoint
|   +-- secrets.py      # regex + entropy detectors
|   +-- deps.py          # manifest parsing + OSV.dev query
|   +-- scoring.py       # severity weighting
|   +-- report.py        # table / JSON / markdown rendering
+-- tests/
|   +-- fixtures/        # planted fake secrets + sample manifests
+-- .github/workflows/   # CI: ruff + pytest on every push
```

---

## Skills This Project Shows

| Area | Technologies |
|---|---|
| Application security | Secret detection patterns, entropy analysis, dependency CVE scanning |
| Python | argparse CLI design, dataclasses, regex, packaging (`pyproject.toml`) |
| Testing | pytest, fixture-based test design, mocked HTTP (`responses`) for deterministic CI |
| CI/CD | GitHub Actions, matrix testing across Python versions, lint gate (ruff) |
| API integration | OSV.dev batch vulnerability query API |

---

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Vansh Khanna
