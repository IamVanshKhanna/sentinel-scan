"""Scan git commit history for secrets that existed in the past, even if removed from HEAD.

Runs `git log -p` and applies the same regex patterns from secrets.py to added lines
(lines starting with '+', excluding the '+++' file-header lines). This catches the
common real-world case: a secret committed, then "removed" in a later commit — it's
still sitting in every clone's history.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from .secrets import COMPILED

COMMIT_HEADER = re.compile(r"^commit ([0-9a-f]{40})")
FILE_HEADER = re.compile(r"^\+\+\+ b/(.+)$")
ADDED_LINE = re.compile(r"^\+(?!\+\+)(.*)$")


@dataclass
class HistoryFinding:
    commit: str
    file: str
    kind: str
    severity: str
    snippet: str


def is_git_repo(path: str) -> bool:
    result = subprocess.run(
        ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def scan_history(path: str, max_commits: int = 500) -> list[HistoryFinding]:
    """Scan up to max_commits of history. Fails soft (empty list) if not a git repo or git errors."""
    if not is_git_repo(path):
        return []

    try:
        result = subprocess.run(
            ["git", "-C", path, "log", "-p", f"-{max_commits}", "--no-color", "--unified=0"],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    if result.returncode != 0:
        return []

    findings: list[HistoryFinding] = []
    current_commit = "unknown"
    current_file = "unknown"

    for line in result.stdout.splitlines():
        commit_match = COMMIT_HEADER.match(line)
        if commit_match:
            current_commit = commit_match.group(1)[:12]
            continue

        file_match = FILE_HEADER.match(line)
        if file_match:
            current_file = file_match.group(1)
            continue

        added_match = ADDED_LINE.match(line)
        if not added_match:
            continue

        content = added_match.group(1)
        for name, pattern, severity in COMPILED:
            if pattern.search(content):
                findings.append(HistoryFinding(
                    commit=current_commit, file=current_file, kind=name,
                    severity=severity, snippet=content.strip()[:120],
                ))

    return findings
