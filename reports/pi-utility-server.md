# sentinel-scan report - `pi-utility-server`

**Triage summary:** Current tree is clean. Git history shows 3 real `.key` files (self-signed local Traefik TLS certs — not internet-exposed production secrets) committed once in an early restructuring commit, later removed — a genuine catch, verified via byte size and absence of placeholder markers. The 30 MEDIUM findings share a single already-deleted commit (`7915a20de760`, the original K3s/ArgoCD/Helmfile experiment, fully removed the very next commit per its own message "clean: remove v2.x artifacts") — repeated identical value-lengths suggest templated/placeholder Helm values rather than distinct real secrets, but individual values weren't manually decoded beyond checking against a common-placeholder denylist.

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
