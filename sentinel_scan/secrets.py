"""Regex + entropy-based secret detection."""

from __future__ import annotations

import fnmatch
import math
import os
import re
from dataclasses import dataclass

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next"}

# Files larger than this are skipped outright — a stray data dump or log file
# shouldn't be read entirely into memory just to be regex-scanned line by line.
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB

BINARY_SNIFF_BYTES = 8192

# Lockfiles are full of legitimate high-entropy hashes (SRI integrity, checksums) —
# scanning them for secrets is pure noise, not signal.
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "Gemfile.lock", "composer.lock",
}

INLINE_IGNORE_MARKER = "sentinel-scan:ignore"

# Filenames that are inherently secret-shaped regardless of content — key material
# files, not just key-material-looking lines.
SECRET_FILENAME_PATTERNS = [
    (re.compile(r".*\.pem$"), "pem_key_file", "critical"),
    (re.compile(r".*\.key$"), "key_file", "critical"),
    (re.compile(r"^id_rsa$|^id_dsa$|^id_ecdsa$|^id_ed25519$"), "ssh_private_key_file", "critical"),
    (re.compile(r"^\.npmrc$"), "npmrc_file", "medium"),
]

# High-confidence, low-false-positive patterns first — these alone are strong signal.
PATTERNS: list[tuple[str, str, str]] = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "critical"),
    ("aws_secret_key", r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", "critical"),
    ("github_token", r"ghp_[A-Za-z0-9]{36}", "critical"),
    ("github_fine_grained", r"github_pat_[A-Za-z0-9_]{22,}", "critical"),
    ("private_key_header", r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----", "critical"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}", "high"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", "high"),
    ("stripe_live_key", r"[sr]k_live_[A-Za-z0-9]{20,}", "critical"),
    ("stripe_test_key", r"[sr]k_test_[A-Za-z0-9]{20,}", "medium"),
    ("jwt_token", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "high"),
    ("db_connection_string_with_creds",
     r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?)://[^:\s]+:[^@\s]+@[^/\s]+", "critical"),
    # Excludes values starting with $ or {{ — those are variable references / template
    # placeholders (${VAR}, $VAR, {{ jinja }}), not literal hardcoded secrets.
    ("generic_secret_assignment",
     r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"](?!\$|\{\{)[^'\"\s]{8,}['\"]",
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


def load_ignore_patterns(root: str) -> list[str]:
    """Read .sentinelignore from the scan root — one glob pattern per line, '#' comments allowed."""
    ignore_path = os.path.join(root, ".sentinelignore")
    patterns: list[str] = []
    try:
        with open(ignore_path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    patterns.append(line)
    except OSError:
        pass
    return patterns


def is_ignored(path: str, root: str, ignore_patterns: list[str]) -> bool:
    rel_path = os.path.relpath(path, root)
    return any(fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(os.path.basename(path), pat)
               for pat in ignore_patterns)


def is_binary(path: str) -> bool:
    """Sniff the first chunk of a file for a null byte — the standard, extension-independent
    signal that a file is binary rather than text. Cheap: reads at most BINARY_SNIFF_BYTES."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(BINARY_SNIFF_BYTES)
    except OSError:
        return True  # unreadable — treat as skip-worthy, not as a scannable text file
    return b"\x00" in chunk


def check_filename(path: str) -> list[Finding]:
    findings: list[Finding] = []
    basename = os.path.basename(path)
    for pattern, kind, severity in SECRET_FILENAME_PATTERNS:
        if pattern.match(basename):
            findings.append(Finding(file=path, line=0, kind=kind, severity=severity,
                                     snippet=f"(flagged by filename: {basename})"))
    return findings


def scan_file(path: str) -> list[Finding]:
    # Filename-based detection runs regardless of binary/size status — a binary .pem or
    # .key file is still exactly the kind of thing this check exists to catch.
    findings: list[Finding] = check_filename(path)

    try:
        if os.path.getsize(path) > MAX_FILE_SIZE_BYTES:
            return findings
    except OSError:
        return findings

    if is_binary(path):
        return findings

    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for lineno, line in enumerate(lines, start=1):
        if INLINE_IGNORE_MARKER in line:
            continue

        regex_spans: list[tuple[int, int]] = []
        for name, pattern, severity in COMPILED:
            for m in pattern.finditer(line):
                regex_spans.append(m.span())
                findings.append(Finding(file=path, line=lineno, kind=name, severity=severity,
                                         snippet=line.strip()[:120]))

        # Entropy pass — only skipped for a *specific candidate* whose span overlaps a
        # named-pattern match, so one secret isn't double-counted as two findings. A second,
        # independent high-entropy string elsewhere on the same line still gets reported —
        # blanket per-line suppression would silently drop a real second secret.
        if "=" in line or ":" in line:
            for match in QUOTED_STRING.finditer(line):
                span = match.span()
                if any(span[0] < r_end and span[1] > r_start for r_start, r_end in regex_spans):
                    continue
                candidate = match.group(1)
                if shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
                    findings.append(Finding(file=path, line=lineno, kind="high_entropy_string",
                                             severity="low", snippet=line.strip()[:120]))

    return findings


@dataclass
class DirectoryScanResult:
    findings: list[Finding]
    ignored_file_count: int  # files skipped due to .sentinelignore / --exclude — surfaced so
    #                          an ignore rule silently blinding the scan is visible, not silent.


def scan_directory_with_stats(root: str, extra_ignore_patterns: list[str] | None = None) -> DirectoryScanResult:
    ignore_patterns = load_ignore_patterns(root) + (extra_ignore_patterns or [])
    findings: list[Finding] = []
    ignored_file_count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            if filename.endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf")):
                continue
            full_path = os.path.join(dirpath, filename)
            if is_ignored(full_path, root, ignore_patterns):
                ignored_file_count += 1
                continue
            findings.extend(scan_file(full_path))
    return DirectoryScanResult(findings=findings, ignored_file_count=ignored_file_count)


def scan_directory(root: str, extra_ignore_patterns: list[str] | None = None) -> list[Finding]:
    """Convenience wrapper over scan_directory_with_stats() for callers that only need the
    findings list (existing tests, simple scripting use). CLI uses the stats version directly
    to surface how many files an ignore rule suppressed."""
    return scan_directory_with_stats(root, extra_ignore_patterns).findings
