# Changelog

## 0.2.1

Ran the tool against all 10 repos in the account (not just its own fixtures) and verified
a fresh install end-to-end on all 3 major platforms — both surfaced real bugs.

- Fixed two more detector false positives found via cross-repo testing: `${VAR}`/`$VAR`
  env-var references and common placeholder passwords (`***`, `testpass`, `changeme`, etc.)
  were both misflagged as hardcoded database credentials
- `private_key_header` now checks the next 1-2 lines for placeholder markers (`...`, `FAKE`,
  `PLACEHOLDER`) before flagging — a setup doc showing "here's the shape of a key" isn't an
  actually-committed key
- Fixed em-dashes in every runtime output string rendering as `?` on Windows' default
  (non-UTF-8) console codepage — found via a real fresh install on Windows, not assumed
- Fixed Rich's table `overflow="ellipsis"` default (uses U+2026) causing the same
  mangled-character bug on long file paths — applied `overflow="fold"` consistently
- Verified fresh-clone installs on macOS (native), Linux (Docker), and Windows (native,
  Python 3.14) — including real network-failure and `--fail-on` exit-code behavior on each,
  not just on the platform this was developed on
- 50 passing tests (was 45)

## 0.2.0

Result of a 3-round senior-review process — five reviewer personas (AppSec, Staff SWE,
SRE, Adversarial Researcher, Engineering Manager) independently critiqued the codebase
each round; surviving fixes (the ones multiple personas converged on) were implemented,
then reviewed again against the new state. Full reasoning in commit messages.

**Round 1:**
- Fixed a dedup regression where a second, independent secret on a line already matched
  by a named pattern was silently dropped
- `deps.query_osv()` now distinguishes "checked, found nothing" from "check failed" —
  previously both returned an empty list, which fails open on a security verdict
- OSV query timeout scales with dependency batch size instead of a fixed 15s window
- README dropped an unwinnable direct-comparison claim against gitleaks/truffleHog/Snyk

**Round 2:**
- `risk_score()` now includes git-history findings — previously a critical secret found
  only in history scored 0, disagreeing with `--fail-on`'s correct exit code
- `history.scan_history()` gets the same ok/failed result shape just added to `deps.py`
  — "not a git repo" is a valid no-op, an actual git command failure is not silent
- `.sentinelignore`/`--exclude` suppression count is now surfaced in output — an ignore
  rule can no longer silently blind a scan with zero trace in the report
- Replaced a test that asserted nothing real with two that test actual timeout arithmetic

**Round 3:**
- Inline `sentinel-scan:ignore` suppressions are now counted and surfaced (mirrors the
  round-2 fix for file-level ignores) — flagged in all 3 review rounds, addressed in this one
- JSON output carries a `schema_version` field for downstream compatibility checks
- Documented known limitations explicitly in the README instead of leaving them implicit

## 0.1.0

Initial prototype: secret detection (regex + entropy), OSV.dev dependency vulnerability
check, table/JSON/markdown output, git-history scanning, Dockerfile, `.sentinelignore`
support, 15+ detector types.
