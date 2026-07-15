"""Report rendering: table (default), JSON, markdown."""

from __future__ import annotations

import json

from .scoring import risk_score, severity_rank

try:
    from rich.console import Console
    from rich.table import Table
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


def render_table(secret_findings: list, vuln_findings: list, target: str) -> None:
    score = risk_score(secret_findings, vuln_findings)

    if _HAS_RICH:
        console = Console()
        console.print(f"\n[bold]sentinel-scan[/bold] — [dim]{target}[/dim]")
        console.print(f"Risk score: [bold]{score}[/bold]  "
                       f"({len(secret_findings)} secret findings, {len(vuln_findings)} vulnerable dependencies)\n")

        if secret_findings:
            table = Table(title="Secrets")
            table.add_column("Severity")
            table.add_column("File")
            table.add_column("Line")
            table.add_column("Kind")
            table.add_column("Snippet", overflow="fold")
            for f in sorted(secret_findings, key=lambda x: severity_rank(x.severity)):
                table.add_row(f.severity.upper(), f.file, str(f.line), f.kind, f.snippet)
            console.print(table)

        if vuln_findings:
            table = Table(title="Vulnerable Dependencies")
            table.add_column("Severity")
            table.add_column("Package")
            table.add_column("Version")
            table.add_column("Vuln ID")
            table.add_column("Summary", overflow="fold")
            for v in sorted(vuln_findings, key=lambda x: severity_rank(x.severity)):
                table.add_row(v.severity.upper(), v.package, v.version, v.vuln_id, v.summary)
            console.print(table)

        if not secret_findings and not vuln_findings:
            console.print("[green]No findings.[/green]")
    else:
        print(f"sentinel-scan — {target}")
        print(f"Risk score: {score} ({len(secret_findings)} secrets, {len(vuln_findings)} vulnerable deps)")
        for f in sorted(secret_findings, key=lambda x: severity_rank(x.severity)):
            print(f"  [{f.severity.upper()}] {f.file}:{f.line} {f.kind} — {f.snippet}")
        for v in sorted(vuln_findings, key=lambda x: severity_rank(x.severity)):
            print(f"  [{v.severity.upper()}] {v.package}=={v.version} {v.vuln_id} — {v.summary}")


def render_json(secret_findings: list, vuln_findings: list, target: str) -> str:
    return json.dumps({
        "target": target,
        "risk_score": risk_score(secret_findings, vuln_findings),
        "secrets": [f.__dict__ for f in secret_findings],
        "vulnerable_dependencies": [v.__dict__ for v in vuln_findings],
    }, indent=2)


def render_markdown(secret_findings: list, vuln_findings: list, target: str) -> str:
    score = risk_score(secret_findings, vuln_findings)
    lines = [f"# sentinel-scan report — `{target}`", "", f"**Risk score:** {score}", ""]

    lines.append("## Secrets")
    if secret_findings:
        lines.append("| Severity | File | Line | Kind |")
        lines.append("|---|---|---|---|")
        for f in sorted(secret_findings, key=lambda x: severity_rank(x.severity)):
            lines.append(f"| {f.severity.upper()} | `{f.file}` | {f.line} | {f.kind} |")
    else:
        lines.append("No secrets found.")

    lines.append("")
    lines.append("## Vulnerable Dependencies")
    if vuln_findings:
        lines.append("| Severity | Package | Version | Vuln ID |")
        lines.append("|---|---|---|---|")
        for v in sorted(vuln_findings, key=lambda x: severity_rank(x.severity)):
            lines.append(f"| {v.severity.upper()} | {v.package} | {v.version} | {v.vuln_id} |")
    else:
        lines.append("No known-vulnerable dependencies found.")

    return "\n".join(lines)
