"""Rich-based presentation helpers for the CLI.

Centralises colours, severity styling and the findings table so output is
consistent across commands. Respects a quiet mode and a no-colour environment.
"""

from __future__ import annotations

import os

from rich.console import Console
from rich.table import Table
from rich.text import Text

from isahat.core.models import Finding, ScanResult, Severity
from isahat.core.risk import priority_score

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_TEXT: dict[Severity, str] = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def make_console(quiet: bool = False) -> Console:
    no_color = bool(os.environ.get("NO_COLOR"))
    return Console(quiet=quiet, no_color=no_color, stderr=False)


def severity_badge(severity: Severity) -> Text:
    return Text(_SEVERITY_TEXT[severity], style=_SEVERITY_STYLE[severity])


def render_findings_table(console: Console, result: ScanResult) -> None:
    if not result.findings:
        console.print("[green]No findings within the authorised scope.[/green]")
        return

    table = Table(
        title=f"Findings for {result.target}",
        header_style="bold",
        show_lines=False,
        expand=True,
    )
    table.add_column("Sev", width=6, no_wrap=True)
    table.add_column("Confidence", width=12, no_wrap=True)
    table.add_column("Pri", width=4, justify="right", no_wrap=True)
    table.add_column("Title", overflow="fold")
    table.add_column("Endpoint", overflow="fold", style="dim")

    for finding in result.findings:
        table.add_row(
            severity_badge(finding.severity),
            finding.confidence.value,
            str(priority_score(finding)),
            finding.title,
            f"{finding.method} {finding.endpoint}",
        )
    console.print(table)


def render_summary(console: Console, result: ScanResult) -> None:
    counts = result.stats.by_severity
    parts = []
    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        count = counts.get(severity.value, 0)
        if count:
            style = _SEVERITY_STYLE[severity]
            parts.append(f"[{style}]{_SEVERITY_TEXT[severity]}: {count}[/]")
    summary = "  ".join(parts) if parts else "[green]clean[/green]"
    console.print(
        f"\nScan [bold]{result.id}[/bold] — {result.stats.endpoints_discovered} endpoints, "
        f"{result.stats.requests_made} requests, {result.stats.findings_total} findings"
    )
    console.print(summary)


def print_scope_banner(console: Console, target: str, scope_description: str) -> None:
    console.print()
    console.print("[bold yellow]Authorisation check[/bold yellow]")
    console.print(
        "IsaHat must only be used against systems you own or are explicitly authorised to test."
    )
    console.print(f"[bold]Target:[/bold] {target}")
    for line in scope_description.splitlines():
        console.print(f"  {line}")


def finding_detail(finding: Finding) -> str:
    lines = [
        f"[bold]{finding.title}[/bold]",
        f"severity={finding.severity.value} confidence={finding.confidence.value} "
        f"priority={priority_score(finding)}",
        f"endpoint={finding.method} {finding.endpoint}",
        f"impact: {finding.impact}",
        f"recommendation: {finding.recommendation}",
    ]
    return "\n".join(lines)
