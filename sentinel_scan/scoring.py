"""Severity scoring and sorting."""

from __future__ import annotations

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 99)


def risk_score(secret_findings: list, vuln_findings: list) -> int:
    total = 0
    for f in secret_findings:
        total += SEVERITY_WEIGHT.get(f.severity, 0)
    for v in vuln_findings:
        total += SEVERITY_WEIGHT.get(v.severity, 0)
    return total
