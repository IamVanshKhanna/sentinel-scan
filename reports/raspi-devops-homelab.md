# sentinel-scan report — `raspi-devops-homelab`

**Triage summary:** Same historical K3s/Helmfile lineage as pi-utility-server/homelab-ops-mesh (this repo's `archive/` directories preserve those earlier iterations directly in the working tree, not just history — hence findings appear in both "Secrets" and "Secrets in Git History" sections). The `archive/homelab-prod/scripts/status-report.sh` MEDIUM finding didn't match the placeholder-word denylist and wasn't individually hand-verified — flagged here as genuinely worth a manual look rather than dismissed. Everything else follows the same "dead, already-deleted v0.x infra" pattern as the other two repos.

**Risk score:** 249

## Secrets
| Severity | File | Line | Kind |
|---|---|---|---|
| MEDIUM | `raspi-devops-homelab/archive/homelab-prod/scripts/status-report.sh` | 12 | generic_secret_assignment |

## Vulnerable Dependencies
No known-vulnerable dependencies found.

## Secrets in Git History
| Severity | Commit | File | Kind |
|---|---|---|---|
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
| MEDIUM | `351127f54221` | `scripts/status-report.sh` | generic_secret_assignment |
| MEDIUM | `e9870cd3bc1b` | `config/cluster-api/providers/metal3/README.md` | generic_secret_assignment |
| MEDIUM | `e9870cd3bc1b` | `config/cluster-api/providers/metal3/README.md` | generic_secret_assignment |
| MEDIUM | `e9870cd3bc1b` | `config/cluster-api/providers/metal3/bmc-secret-pi4.yaml` | generic_secret_assignment |
| MEDIUM | `e9870cd3bc1b` | `config/cluster-api/providers/metal3/bmc-secret-pi5.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `c140275ad7ae` | `helmfile/values/defaults.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
| MEDIUM | `21cc22a09b63` | `argocd/applications/homelab-values-configmap.yaml` | generic_secret_assignment |
