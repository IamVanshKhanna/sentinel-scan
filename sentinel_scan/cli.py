"""sentinel-scan entrypoint."""

from __future__ import annotations

import argparse
import sys

from . import __version__, deps, history, report, secrets
from .scoring import severity_rank

FAIL_ON_THRESHOLD = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-scan",
        description="Scan a repository for hardcoded secrets and known-vulnerable dependencies.",
    )
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument("--version", action="version", version=f"sentinel-scan {__version__}")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a table")
    parser.add_argument("--markdown", action="store_true", help="Output Markdown instead of a table")
    parser.add_argument("--no-deps", action="store_true", help="Skip the dependency vulnerability check")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                         help="Glob pattern to exclude (repeatable). Supplements .sentinelignore, doesn't replace it.")
    parser.add_argument("--history", action="store_true",
                         help="Also scan git commit history for secrets removed from HEAD but still present in old commits")
    parser.add_argument("--max-commits", type=int, default=500,
                         help="Max commits to scan with --history (default: 500)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                         default="none", help="Exit non-zero if a finding at or above this severity exists")
    args = parser.parse_args(argv)

    secret_scan = secrets.scan_directory_with_stats(args.path, extra_ignore_patterns=args.exclude)
    secret_findings = secret_scan.findings

    vuln_findings = []
    deps_check_ok = True
    if not args.no_deps:
        found_deps = deps.find_manifests(args.path)
        osv_result = deps.query_osv(found_deps)
        vuln_findings = osv_result.findings
        deps_check_ok = osv_result.ok

    history_findings = []
    history_check_ok = True
    if args.history:
        history_result = history.scan_history(args.path, max_commits=args.max_commits)
        history_findings = history_result.findings
        history_check_ok = history_result.ok

    if args.json:
        print(report.render_json(secret_findings, vuln_findings, args.path, history_findings, deps_check_ok))
    elif args.markdown:
        print(report.render_markdown(secret_findings, vuln_findings, args.path, history_findings, deps_check_ok))
    else:
        report.render_table(secret_findings, vuln_findings, args.path, history_findings, deps_check_ok)

    if secret_scan.ignored_file_count > 0:
        print(f"\n{secret_scan.ignored_file_count} file(s) skipped by .sentinelignore / --exclude rules.",
              file=sys.stderr)
    if not deps_check_ok:
        print("WARNING: dependency vulnerability check failed (network/API error) — "
              "results are INCOMPLETE, not verified clean.", file=sys.stderr)
    if args.history and not history_check_ok:
        print("WARNING: git history scan failed (git command error/timeout) — "
              "history results are INCOMPLETE, not verified clean.", file=sys.stderr)

    if args.fail_on != "none":
        threshold = FAIL_ON_THRESHOLD[args.fail_on]
        all_severities = (
            [f.severity for f in secret_findings]
            + [v.severity for v in vuln_findings]
            + [h.severity for h in history_findings]
        )
        if any(severity_rank(s) <= threshold for s in all_severities):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
