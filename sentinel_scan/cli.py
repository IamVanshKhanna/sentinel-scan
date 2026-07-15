"""sentinel-scan entrypoint."""

from __future__ import annotations

import argparse
import sys

from . import deps, history, report, secrets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-scan",
        description="Scan a repository for hardcoded secrets and known-vulnerable dependencies.",
    )
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a table")
    parser.add_argument("--markdown", action="store_true", help="Output Markdown instead of a table")
    parser.add_argument("--no-deps", action="store_true", help="Skip the dependency vulnerability check")
    parser.add_argument("--history", action="store_true",
                         help="Also scan git commit history for secrets removed from HEAD but still present in old commits")
    parser.add_argument("--max-commits", type=int, default=500,
                         help="Max commits to scan with --history (default: 500)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                         default="none", help="Exit non-zero if a finding at or above this severity exists")
    args = parser.parse_args(argv)

    secret_findings = secrets.scan_directory(args.path)

    vuln_findings = []
    if not args.no_deps:
        found_deps = deps.find_manifests(args.path)
        vuln_findings = deps.query_osv(found_deps)

    history_findings = []
    if args.history:
        history_findings = history.scan_history(args.path, max_commits=args.max_commits)

    if args.json:
        print(report.render_json(secret_findings, vuln_findings, args.path, history_findings))
    elif args.markdown:
        print(report.render_markdown(secret_findings, vuln_findings, args.path, history_findings))
    else:
        report.render_table(secret_findings, vuln_findings, args.path, history_findings)

    if args.fail_on != "none":
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
        from .scoring import severity_rank
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
