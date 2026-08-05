"""Markdown reporter — a human-readable audit report.

Structure follows the documented report layout: executive summary, scope,
methodology, statistics, discovered surface, then detailed findings ordered by
priority.
"""

from __future__ import annotations

from isahat.core.models import ScanResult, Severity
from isahat.core.risk import priority_score

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informative",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _summary_table(result: ScanResult) -> str:
    counts = result.stats.by_severity
    lines = ["| Severity | Count |", "| --- | --- |"]
    for severity in _SEVERITY_ORDER:
        lines.append(f"| {_SEVERITY_LABEL[severity]} | {counts.get(severity.value, 0)} |")
    lines.append(f"| **Total** | **{result.stats.findings_total}** |")
    return "\n".join(lines)


def _duration(result: ScanResult) -> str:
    if not result.finished_at:
        return "n/a"
    delta = result.finished_at - result.started_at
    return f"{delta.total_seconds():.1f}s"


def to_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# IsaHat Security Audit — {result.target}")
    add("")
    add(f"- **Scan ID:** `{result.id}`")
    add(f"- **Profile:** {result.profile}")
    add(f"- **Type:** {result.scan_type}")
    add(f"- **Started:** {result.started_at.isoformat()}")
    add(f"- **Duration:** {_duration(result)}")
    add(f"- **IsaHat version:** {result.isahat_version or 'n/a'}")
    add("")

    add("## Executive summary")
    add("")
    total = result.stats.findings_total
    crit = result.stats.by_severity.get("critical", 0)
    high = result.stats.by_severity.get("high", 0)
    if total == 0:
        add("No findings were produced by the enabled detectors within the authorised scope.")
    else:
        add(
            f"IsaHat produced **{total} finding(s)** within the authorised scope, "
            f"including **{crit} critical** and **{high} high** severity item(s). "
            "Each finding lists a separate confidence level; review confidence before acting."
        )
    add("")
    add(_summary_table(result))
    add("")

    add("## Scope & authorisation")
    add("")
    add("> Scans must only target systems you own or are explicitly authorised to test.")
    add("")
    add(f"- **Target:** {result.scope.target}")
    add(f"- **Allowed hosts:** {', '.join(result.scope.allowed_hosts) or 'n/a'}")
    add(f"- **Include paths:** {', '.join(result.scope.include) or '(all)'}")
    add(f"- **Exclude paths:** {', '.join(result.scope.exclude) or '(none)'}")
    add("")

    add("## Methodology & limitations")
    add("")
    add(
        "Passive header/cookie analysis and a small allowlist of non-destructive checks were "
        "run against traffic captured by a scope-bound crawler. This is not a substitute for a "
        "full manual penetration test; absence of findings does not prove absence of risk."
    )
    add("")

    add("## Discovered surface")
    add("")
    add(f"- **Endpoints discovered:** {result.stats.endpoints_discovered}")
    add(f"- **Requests made:** {result.stats.requests_made}")
    if result.technologies:
        techs = ", ".join(
            f"{t.name}{f' {t.version}' if t.version else ''}" for t in result.technologies
        )
        add(f"- **Technologies:** {techs}")
    add("")

    add("## Findings")
    add("")
    if not result.findings:
        add("_No findings._")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(result.findings, start=1):
        add(
            f"### {index}. {finding.title} "
            f"[{_SEVERITY_LABEL[finding.severity]} · confidence: {finding.confidence.value}]"
        )
        add("")
        add(f"- **ID:** `{finding.id}`")
        add(f"- **Category:** {finding.category}")
        add(f"- **Priority score:** {priority_score(finding)}/100")
        if finding.cwe:
            add(f"- **CWE:** {finding.cwe}")
        if finding.owasp:
            add(f"- **OWASP:** {finding.owasp}")
        add(f"- **Endpoint:** `{finding.method} {finding.endpoint}`")
        if finding.parameter:
            add(f"- **Parameter:** `{finding.parameter}`")
        add(f"- **State:** {finding.state.value}")
        add("")
        add(f"**Impact.** {finding.impact}")
        add("")
        add(f"**Evidence.** {finding.evidence.summary}")
        if finding.evidence.response:
            add("")
            add("```")
            add(finding.evidence.response)
            add("```")
        add("")
        add(f"**Recommendation.** {finding.recommendation}")
        if finding.remediation_example:
            add("")
            add("```")
            add(finding.remediation_example)
            add("```")
        if finding.false_positive_hints:
            add("")
            add("**Possible false positives.**")
            for hint in finding.false_positive_hints:
                add(f"- {hint}")
        if finding.references:
            add("")
            add("**References.**")
            for ref in finding.references:
                add(f"- {ref}")
        add("")
        add("---")
        add("")

    return "\n".join(lines) + "\n"
