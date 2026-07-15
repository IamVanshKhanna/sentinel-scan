"""Regex + entropy-based secret detection."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next"}

# Lockfiles are full of legitimate high-entropy hashes (SRI integrity, checksums) —
# scanning them for secrets is pure noise, not signal.
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "Gemfile.lock", "composer.lock",
}

# High-confidence, low-false-positive patterns first — these alone are strong signal.
PATTERNS: list[tuple[str, str, str]] = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "critical"),
    ("aws_secret_key", r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", "critical"),
    ("github_token", r"ghp_[A-Za-z0-9]{36}", "critical"),
    ("github_fine_grained", r"github_pat_[A-Za-z0-9_]{22,}", "critical"),
    ("private_key_header", r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----", "critical"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}", "high"),
    ("generic_secret_assignment",
     r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
     "medium"),
]

COMPILED = [(name, re.compile(pattern), severity) for name, pattern, severity in PATTERNS]


@dataclass
class Finding:
    file: str
    line: int
    kind: str
    severity: str
    snippet: str


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


QUOTED_STRING = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{20,})['"]""")
ENTROPY_THRESHOLD = 4.3  # empirically: random base64/hex secrets sit well above this; words/paths sit below


def scan_file(path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for lineno, line in enumerate(lines, start=1):
        for name, pattern, severity in COMPILED:
            if pattern.search(line):
                findings.append(Finding(file=path, line=lineno, kind=name, severity=severity,
                                         snippet=line.strip()[:120]))

        # Entropy pass — only on lines that look like an assignment, to keep false positives low.
        if "=" in line or ":" in line:
            for match in QUOTED_STRING.finditer(line):
                candidate = match.group(1)
                if shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
                    findings.append(Finding(file=path, line=lineno, kind="high_entropy_string",
                                             severity="low", snippet=line.strip()[:120]))

    return findings


def scan_directory(root: str) -> list[Finding]:
    import os

    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            if filename.endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf")):
                continue
            findings.extend(scan_file(os.path.join(dirpath, filename)))
    return findings
