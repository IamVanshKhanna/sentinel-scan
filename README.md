# sentinel-scan

> A CLI that scans a repository for hardcoded secrets and known-vulnerable dependencies, and outputs a scored report — table, JSON, or Markdown.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/IamVanshKhanna/sentinel-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/IamVanshKhanna/sentinel-scan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Platforms](https://img.shields.io/badge/tested%20on-macOS%20%7C%20Linux%20%7C%20Windows-success)](#tested-on)

---

## Table of Contents

- [What It Does](#what-it-does)
- [Tested On](#tested-on)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Five-minute demo](#five-minute-demo)
- [Usage](#usage)
- [What to Expect](#what-to-expect)
- [Pros and Cons](#pros-and-cons)
- [How Detection Works](#how-detection-works)
- [Known Limitations](#known-limitations)
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

## Tested On

Not a "should work everywhere, Python is Python" claim — a fresh clone → venv → install → run was actually done on each platform, including forcing a real network failure to confirm the tool fails visibly rather than silently:

| Platform | How it was verified |
|---|---|
| **macOS** | Native venv, fresh clone, full test suite + a real unreachable-host network-failure test |
| **Linux** | Docker (`python:3.12-slim`), built and run against a real external repo; CI (GitHub Actions, `ubuntu-latest`) runs the full suite on every push |
| **Windows** | Fresh SSH session to a real Windows machine (Python 3.14, git 2.54) — clone, venv, install, all 50 tests passing, `--fail-on` exit code verified via PowerShell, network-failure behavior confirmed |

Two real bugs were found doing this, not hypothesized: em-dashes in console output rendered as `?` on Windows' default (non-UTF-8) console codepage, and a Rich table's default truncation style caused the same mangling on long file paths. Both fixed and re-verified on the actual Windows machine before being called done — see [CHANGELOG.md](CHANGELOG.md).

---

## How It Works

Point it at a directory and it runs a fixed pipeline:

1. **Walk the tree.** Skips `.git`, `node_modules`, `venv`, build output, and lockfiles (`package-lock.json` etc. — full of legitimate high-entropy hashes, pure noise for secret detection). Binary files are sniffed (null-byte check) and skipped for content scanning, but a binary `.pem`/`.key`/`id_rsa` is still flagged by filename alone. Files over 5MB are skipped outright.
2. **Scan each remaining file, line by line.** ~15 regex patterns catch specific credential shapes (AWS keys, GitHub/Slack/Stripe tokens, JWTs, DB connection strings, private key headers). A Shannon-entropy check on quoted strings catches high-randomness values the named patterns miss — but only where a named pattern hasn't already matched that exact span, so one real secret isn't double-counted as two findings.
3. **Respect suppression rules**, and say so. A `.sentinelignore` file (glob patterns), `--exclude PATTERN` flags, and inline `# sentinel-scan:ignore` comments all suppress findings — but the *count* of what got suppressed is always printed, so a broad ignore rule can't silently blind the scan without leaving a trace in the output.
4. **Check dependencies, if any exist.** Parses `requirements.txt`/`package.json`, sends everything found to [OSV.dev](https://osv.dev) in one batched query (no API key, real live CVE data). If that network call fails, the report says so explicitly — an empty result and a *failed* result are never rendered identically, because a security tool silently reporting "clean" when it never actually checked is the wrong default.
5. **Optionally walk git history** (`--history`) — the same regex set runs against every added line (`git log -p`) across up to `--max-commits` commits, catching a secret that was committed then "removed" in a later commit but is still sitting in every clone's history.
6. **Score and render.** Every finding gets a severity; a weighted total (critical=10, high=6, medium=3, low=1) becomes the headline risk score. Output is a Rich-formatted table by default, or `--json`/`--markdown` for piping into something else.
7. **Optionally gate on severity.** `--fail-on critical` (or high/medium/low) exits 1 if a finding at or above that severity exists — the hook for wiring this into CI.

---

## Quick Start

```bash
git clone https://github.com/IamVanshKhanna/sentinel-scan.git
cd sentinel-scan
pip install -e ".[dev]"

sentinel-scan .
```

## Five-minute demo

The [`demo/`](demo/README.md) walkthrough is a safe local target: fake key-like
text, an old sample dependency, offline detection, JSON/Markdown output, and a
non-zero CI gate. No real secret or third-party repository is needed. Start with:

```bash
sentinel-scan demo --no-deps --json
sentinel-scan demo --no-deps --fail-on medium
```

The second command exits 1 because the deliberately fake key-like value is
found. See [the full demo](demo/README.md) for the optional live OSV lookup
and expected output fields. Exit 2 means the dependency/history check failed
or the command-line arguments were invalid - not that a scan found no issues.

## Usage

```bash
sentinel-scan /path/to/repo                 # table output
sentinel-scan /path/to/repo --json          # machine-readable
sentinel-scan /path/to/repo --markdown      # for a PR comment or report
sentinel-scan /path/to/repo --no-deps       # secrets only, skip network call
sentinel-scan /path/to/repo --fail-on high  # exit 1 if a high/critical finding exists — CI-friendly
```

---

## What to Expect

A clean repo prints exactly this — no noise, no "probably fine, we didn't really check":

```
sentinel-scan — /path/to/repo
Risk score: 0  (0 secret findings, 0 vulnerable dependencies, 0 in git history)

No findings.
```

A repo with a real finding looks like this (illustrative example — not a live credential):

```
sentinel-scan — /path/to/repo
Risk score: 13  (2 secret findings, 1 vulnerable dependencies, 0 in git history)

                                    Secrets
┏━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ File        ┃ Line ┃ Kind                   ┃ Snippet                 ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ config.py   │ 12   │ aws_access_key         │ AWS_KEY = "AKIA..."    │
│ MEDIUM   │ app.py      │ 40   │ generic_secret_assign… │ api_key = "..."         │
└──────────┴─────────────┴──────┴────────────────────────┴─────────────────────────┘

                              Vulnerable Dependencies
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Package  ┃ Version ┃ Vuln ID         ┃ Summary                     ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ requests │ 2.6.0   │ GHSA-xxxx-xxxx  │ ...                          │
└──────────┴──────────┴─────────┴─────────────────┴──────────────────────────────┘
```

If a `.sentinelignore` or `--exclude` rule suppressed anything, or the dependency/history check failed to complete, that's printed too — always visible, never folded silently into "0 findings":

```
2 file(s) skipped by .sentinelignore / --exclude rules.
1 line(s) suppressed by inline 'sentinel-scan:ignore' markers.
WARNING: dependency vulnerability check failed (network/API error) — results are INCOMPLETE, not verified clean.
```

`--fail-on critical` (or high/medium/low) turns any of the above into a non-zero exit code — that's the whole CI integration story, no extra flags needed beyond picking a threshold.

---

## Pros and Cons

**Pros**
- Zero setup cost for the dependency check — OSV.dev needs no account, no API key, no rate-limit dance.
- A failed check is never disguised as a clean result — dependency, history, and suppression state are all explicitly surfaced, not silently folded into "0 findings."
- Small enough to read end to end in one sitting — each concern (detection, scoring, reporting, CLI) is its own ~100-line file, not a framework.
- Runs anywhere Python 3.10+ or Docker runs — no service to stand up, no account to create.
- CI-ready out of the box: `--fail-on` + a real exit code, `--json`/`--markdown` for piping into a dashboard or PR comment.

**Cons** — see [Known Limitations](#known-limitations) for the full, honest list, but the short version:
- Regex + entropy detection has a real, structural ceiling — obfuscated or split secrets aren't caught, by this or any tool in the same category.
- Not corpus-calibrated. The entropy threshold and pattern list are reasoned about, not tuned against years of real-world false-positive data the way gitleaks/truffleHog's are.
- `--history` only sees the current branch's linear commit log — squash-merged-away branch history isn't covered.

---

## How Detection Works

**Secrets** — a small set of high-confidence patterns (not a giant unmaintained regex list) plus entropy scoring. Every detector is unit-tested against planted fake secrets in [`tests/fixtures/`](tests/fixtures/) — fake by construction (correct format, not live credentials), so the test suite doesn't itself leak anything or trip other scanners.

**Dependencies** — `requirements.txt`/`package.json` are parsed into `(name, version, ecosystem)` tuples and sent to OSV.dev's batch query API in one request. Network calls are mocked in tests (via `responses`) so the suite runs fully offline and deterministically.

**Design choice:** OSV.dev over a bundled static vulnerability database — real, continuously updated data instead of a snapshot that goes stale the day it ships.

---

## Known Limitations

Documented explicitly rather than left implicit — this doesn't try to be a complete tool, and pretending otherwise would undercut the point of building something small and understandable:

- **Won't catch obfuscated or split secrets.** A key concatenated across two string literals, base64-wrapped, or built at runtime from fragments defeats every regex-and-entropy scanner in this category, not just this one.
- **`.sentinelignore` uses `fnmatch` glob semantics, not `.gitignore` semantics** — no `**` recursive-directory matching. A pattern that looks like it should match nested paths the way `.gitignore` does may not; test your patterns before relying on them.
- **`--history` only walks the current branch's linear history** via `git log -p`. A secret that only ever existed on a squash-merged feature branch (and was squashed away before merge) won't show up.
- **Suppression is visible-but-unaudited, not access-controlled.** `.sentinelignore`, `--exclude`, and inline `sentinel-scan:ignore` markers are counted and surfaced in output (so a suppression rule can't silently blind a scan with zero trace), but anyone with write access to the repo can add one — there's no separate authorization step, which is a proportionate tradeoff for a single-user CLI, not a claim this is safe for an adversarial multi-contributor setting without review.
- **Entropy threshold (`4.3`) is empirically chosen, not calibrated against a labeled corpus.** It's the same category of technique gitleaks/truffleHog use, without their years of tuning against real-world false-positive/negative data.

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
+-- reports/             # real scan reports run against other repos in this account
+-- .github/workflows/   # CI: ruff + pytest on every push
```

See [`reports/`](reports/) for real output — this tool run against 4 other real repos, findings triaged by hand, not raw output dumped uncritically.

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
