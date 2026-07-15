# Changelog

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
