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


@dataclass
class HistoryScanResult:
    findings: list[HistoryFinding]
    ok: bool  # False means the git command itself failed — distinct from "not a git repo"
    #           (which is a valid no-op, ok=True) and from "ran clean, found nothing".


def is_git_repo(path: str) -> bool:
    result = subprocess.run(
        ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def scan_history(path: str, max_commits: int = 500) -> HistoryScanResult:
    """Scan up to max_commits of history.

    Not being a git repo is a valid no-op (ok=True, empty findings) — most scan targets
    won't be repos and --history shouldn't look like a failure for that. An actual git
    command error (timeout, non-zero exit, OSError) sets ok=False so callers can tell
    "history scan never really ran" apart from "ran clean, nothing found in history".
    """
    if not is_git_repo(path):
        return HistoryScanResult(findings=[], ok=True)

    try:
        result = subprocess.run(
            ["git", "-C", path, "log", "-p", f"-{max_commits}", "--no-color", "--unified=0"],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return HistoryScanResult(findings=[], ok=False)

    if result.returncode != 0:
        return HistoryScanResult(findings=[], ok=False)

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

    return HistoryScanResult(findings=findings, ok=True)
