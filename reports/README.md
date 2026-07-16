# sentinel-scan — scan reports across all 10 repos

Run `sentinel-scan --history --max-commits 500 --markdown` against every repo in this account (Gitea, mirrors current with GitHub) as both a real-world test of the tool and an honest inventory of what's actually sitting in these repos' history. Each report below includes a **Triage summary** — what was manually verified vs. flagged for review, not just raw tool output presented uncritically.

Two real detector bugs were found and fixed *during* this process (both from actual false positives on real repos, not hypothetical): a `${VAR}`-style env-var reference misflagged as a hardcoded DB credential, and placeholder/example values (`***`, `testpass`, `...`) in template/doc files misflagged as real secrets and private keys. Both are now regression-tested in `sentinel-scan`'s own suite (50 tests, up from 45).

| Repo | Risk Score | Summary |
|---|---|---|
| [pi-utility-server](pi-utility-server.md) | 153 | Current tree clean. Real historical `.key` files (self-signed local certs, since removed) + bulk MEDIUM findings from one already-deleted v0.x commit. |
| [homelab-ops-mesh](homelab-ops-mesh.md) | 153 | Same lineage as pi-utility-server. One live false positive found and fixed here (`${INFISICAL_DB_PASSWORD}` misflagged). |
| [raspi-devops-homelab](raspi-devops-homelab.md) | 249 | Same historical lineage, preserved directly in `archive/` (not just git history). One MEDIUM finding not fully verified — flagged for manual review. |
| [deakin-coursework](deakin-coursework.md) | 954 | Highest real score — actual `.pem`/`key.pem` files from university networking coursework, almost certainly self-signed lab certs, not production secrets, but real key material nonetheless. |
| [devpilot](devpilot.md) | 120 | Secrets section was 100% false positives (placeholder passwords, doc-shown key format) — confirmed and fixed. Remaining score is real: `next@14.2.0` has ~26 known CVEs. |
| [digital-operations-analytics](digital-operations-analytics.md) | 0 | Genuinely clean. |
| [vansh-local-ai-stack](vansh-local-ai-stack.md) | 0 | Genuinely clean. |
| [iamvanshkhanna](iamvanshkhanna.md) | 0 | Profile README repo, nothing to find. |
| [reusable-formats](reusable-formats.md) | 0 | Clean, as expected (templates/docs only). |
| [sentinel-scan](sentinel-scan.md) | 677 | Expected — the tool scanning its own deliberately-planted test fixtures. A 0 here would be the actual red flag. |

## What this demonstrates

- The tool works against real, varied codebases — not just its own curated fixtures.
- Self-testing at scale (10 repos, not 1) surfaced real detector bugs that a single-repo test never would have — both fixed with regression tests before this report was finalized.
- Findings are triaged, not dumped — every non-zero score above has an honest note on what was manually verified vs. what's flagged but unconfirmed. A security tool's report is only as useful as the judgment applied to reading it.
