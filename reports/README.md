# sentinel-scan — scan reports for the featured portfolio repos

Run `sentinel-scan --history --max-commits 500 --markdown` against the 4 repos chosen to represent the portfolio (infra, data, security tooling, and local AI tooling — no overlap, no dead weight). Each report includes a **Triage summary** — what was manually verified vs. flagged for review, not raw tool output presented uncritically.

| Repo | Risk Score | Summary |
|---|---|---|
| [pi-utility-server](pi-utility-server.md) | 153 | Current tree clean. Real historical `.key` files (self-signed local certs, since removed) + bulk MEDIUM findings from one already-deleted v0.x commit. |
| [digital-operations-analytics](digital-operations-analytics.md) | 0 | Genuinely clean. |
| [vansh-local-ai-stack](vansh-local-ai-stack.md) | 0 | Genuinely clean. |
| [sentinel-scan](sentinel-scan.md) | 747 | Expected — the tool scanning its own deliberately-planted test fixtures. A 0 here would be the actual red flag. |

## What this demonstrates

- The tool works against real, varied codebases — not just its own curated fixtures.
- Findings are triaged, not dumped — every non-zero score above has an honest note on what was manually verified vs. what's flagged but unconfirmed.
- Two real detector bugs (a `${VAR}`-style env-var reference and placeholder/example values like `***`/`testpass` misflagged as real secrets) were found and fixed during this exact process — both are now regression-tested in `sentinel-scan`'s own suite.
