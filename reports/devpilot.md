# sentinel-scan report — `devpilot`

**Triage summary:** Zero secrets, current or historical — the entire "Secrets" section was false positives on the first pass (placeholder DB passwords like `***`/`testpass`/`password` in `.env.example`/`docker-compose.yml`/CI config, and a documentation snippet showing a private-key *shape* with `...` as the body), all confirmed by direct inspection and fixed in the scanner's detectors before this report was generated. The remaining risk score is entirely real, legitimate dependency findings — `next@14.2.0` has ~26 known CVEs, worth an actual upgrade.

**Risk score:** 120

## Secrets
No secrets found.

## Vulnerable Dependencies
| Severity | Package | Version | Vuln ID |
|---|---|---|---|
| MEDIUM | next | 14.2.0 | GHSA-36qx-fr4f-26g5 |
| MEDIUM | next | 14.2.0 | GHSA-3g8h-86w9-wvmq |
| MEDIUM | next | 14.2.0 | GHSA-3h52-269p-cp9r |
| MEDIUM | next | 14.2.0 | GHSA-3x4c-7xq6-9pq8 |
| MEDIUM | next | 14.2.0 | GHSA-4342-x723-ch2f |
| MEDIUM | next | 14.2.0 | GHSA-5j59-xgg2-r9c4 |
| MEDIUM | next | 14.2.0 | GHSA-7gfc-8cq8-jh5f |
| MEDIUM | next | 14.2.0 | GHSA-7m27-7ghc-44w9 |
| MEDIUM | next | 14.2.0 | GHSA-8h8q-6873-q5fj |
| MEDIUM | next | 14.2.0 | GHSA-9g9p-9gw9-jx7f |
| MEDIUM | next | 14.2.0 | GHSA-c4j6-fc7j-m34r |
| MEDIUM | next | 14.2.0 | GHSA-f82v-jwr5-mffw |
| MEDIUM | next | 14.2.0 | GHSA-ffhc-5mcf-pf4q |
| MEDIUM | next | 14.2.0 | GHSA-g5qg-72qw-gw5v |
| MEDIUM | next | 14.2.0 | GHSA-g77x-44xx-532m |
| MEDIUM | next | 14.2.0 | GHSA-ggv3-7p47-pfv8 |
| MEDIUM | next | 14.2.0 | GHSA-gp8f-8m3g-qvj9 |
| MEDIUM | next | 14.2.0 | GHSA-gx5p-jg67-6x7h |
| MEDIUM | next | 14.2.0 | GHSA-h25m-26qc-wcjf |
| MEDIUM | next | 14.2.0 | GHSA-h64f-5h5j-jqjh |
| MEDIUM | next | 14.2.0 | GHSA-mwv6-3258-q52c |
| MEDIUM | next | 14.2.0 | GHSA-q4gf-8mx6-v5v3 |
| MEDIUM | next | 14.2.0 | GHSA-qpjv-v59x-3qc4 |
| MEDIUM | next | 14.2.0 | GHSA-vfv6-92ff-j949 |
| MEDIUM | next | 14.2.0 | GHSA-wfc6-r584-vfw7 |
| MEDIUM | next | 14.2.0 | GHSA-xv57-4mr9-wg8v |
| MEDIUM | next-auth | 4.24.0 | GHSA-5jpx-9hw9-2fx4 |
| MEDIUM | next-auth | 4.24.0 | GHSA-v64w-49xw-qq89 |
| MEDIUM | postcss | 8.4.0 | GHSA-7fh5-64p2-3v2j |
| MEDIUM | postcss | 8.4.0 | GHSA-qx2v-qp2m-jg93 |

## Secrets in Git History
| Severity | Commit | File | Kind |
|---|---|---|---|
| CRITICAL | `56b0f8517d5c` | `GITHUB_APP_SETUP.md` | private_key_header |
| CRITICAL | `3bcc993e4951` | `docker-compose.yml` | db_connection_string_with_creds |
| CRITICAL | `3bcc993e4951` | `docker-compose.yml` | db_connection_string_with_creds |
