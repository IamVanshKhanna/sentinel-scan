# sentinel-scan report — `homelab-ops-mesh`

**Triage summary:** Same lineage as pi-utility-server (shared early history) — current tree clean. The 3 CRITICAL history findings are the same real, since-removed `.key` files. A live-tree false positive found during this scan (`windows/stacks/secrets/docker-compose.yml`, a `${INFISICAL_DB_PASSWORD}` env-var reference misflagged as a hardcoded connection string) led directly to a detector fix in `sentinel-scan` itself before this report was generated — see the tool's own repo/CHANGELOG.

**Risk score:** 153

## Secrets
No secrets found.

## Vulnerable Dependencies
No known-vulnerable dependencies found.

## Secrets in Git History
| Severity | Commit | File | Kind |
|---|---|---|---|
| CRITICAL | `0b4fed3c902f` | `pi/config/traefik/certs/ca.key` | private_key_header |
| CRITICAL | `0b4fed3c902f` | `pi/config/traefik/certs/wildcard.key` | private_key_header |
| CRITICAL | `0b4fed3c902f` | `pi/config/traefik/dashboard.key` | private_key_header |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/cluster-api/providers/metal3/README.md` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/cluster-api/providers/metal3/README.md` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/cluster-api/providers/metal3/bmc-secret-pi4.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/cluster-api/providers/metal3/bmc-secret-pi5.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `infra/helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `7915a20de760` | `scripts/status-report.sh` | generic_secret_assignment |
