from sentinel_scan.history import HistoryFinding
from sentinel_scan.scoring import risk_score
from sentinel_scan.secrets import Finding


def test_risk_score_includes_history_findings():
    """A critical secret sitting only in git history must still count toward the score —
    otherwise the headline number can read 'clean' while --fail-on correctly flags it."""
    history_finding = HistoryFinding(commit="abc123", file="old.py", kind="aws_access_key",
                                      severity="critical", snippet="...")
    score_without_history = risk_score([], [])
    score_with_history = risk_score([], [], [history_finding])
    assert score_without_history == 0
    assert score_with_history == 10


def test_risk_score_sums_across_all_three_sources():
    secret = Finding(file="a.py", line=1, kind="aws_access_key", severity="critical", snippet="...")
    history_finding = HistoryFinding(commit="abc", file="b.py", kind="github_token",
                                      severity="critical", snippet="...")
    score = risk_score([secret], [], [history_finding])
    assert score == 20  # 10 (critical secret) + 10 (critical history finding)
