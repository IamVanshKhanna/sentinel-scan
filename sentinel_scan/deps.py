"""Parse dependency manifests and check them against OSV.dev for known vulnerabilities."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str


@dataclass
class VulnFinding:
    package: str
    version: str
    vuln_id: str
    severity: str
    summary: str


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)\s*$")


def parse_requirements_txt(path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                m = REQ_LINE.match(line)
                if m:
                    deps.append(Dependency(name=m.group(1), version=m.group(2),
                                            ecosystem="PyPI", manifest=path))
    except OSError:
        pass
    return deps


def parse_package_json(path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return deps

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean_version = re.sub(r"^[\^~>=<]+", "", version)
            deps.append(Dependency(name=name, version=clean_version, ecosystem="npm", manifest=path))
    return deps


def find_manifests(root: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "venv", ".venv"}]
        if "requirements.txt" in filenames:
            deps.extend(parse_requirements_txt(os.path.join(dirpath, "requirements.txt")))
        if "package.json" in filenames:
            deps.extend(parse_package_json(os.path.join(dirpath, "package.json")))
    return deps


def query_osv(deps: list[Dependency], timeout: float = 15.0) -> list[VulnFinding]:
    """Batch-query OSV.dev for known vulnerabilities. Fails soft (empty list) on network error."""
    if not deps:
        return []

    queries = [
        {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
        for d in deps
    ]

    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except (requests.RequestException, ValueError):
        return []

    findings: list[VulnFinding] = []
    for dep, result in zip(deps, results):
        for vuln in result.get("vulns", []) or []:
            severity = _extract_severity(vuln)
            findings.append(VulnFinding(
                package=dep.name,
                version=dep.version,
                vuln_id=vuln.get("id", "UNKNOWN"),
                severity=severity,
                summary=(vuln.get("summary") or "No summary available")[:200],
            ))
    return findings


def _extract_severity(vuln: dict) -> str:
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "")
        if isinstance(score, str) and "/" in score:
            try:
                val = float(score.split("/")[0])
                if val >= 9.0:
                    return "critical"
                if val >= 7.0:
                    return "high"
                if val >= 4.0:
                    return "medium"
                return "low"
            except ValueError:
                continue
    return "medium"  # unscored OSV entries default to medium, not silently ignored
