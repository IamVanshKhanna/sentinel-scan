"""Severity scoring and sorting."""

from __future__ import annotations

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 99)


def risk_score(secret_findings: list, vuln_findings: list, history_findings: list | None = None) -> int:
    total = 0
    for f in secret_findings:
        total += SEVERITY_WEIGHT.get(f.severity, 0)
    for v in vuln_findings:
        total += SEVERITY_WEIGHT.get(v.severity, 0)
    for h in history_findings or []:
        total += SEVERITY_WEIGHT.get(h.severity, 0)
    return total
