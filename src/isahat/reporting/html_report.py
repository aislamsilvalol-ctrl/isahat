"""Self-contained HTML reporter.

Produces a single ``.html`` file with inline CSS — no external assets, no
JavaScript. Security note: evidence can contain attacker-controlled payloads
(e.g. XSS markers), so **every** dynamic value is HTML-escaped. The report is
intentionally script-free so opening it can never execute captured payloads.
"""

from __future__ import annotations

from html import escape

from isahat import __version__
from isahat.core.models import Finding, ScanResult, Severity
from isahat.core.risk import priority_score

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b3123b",
    Severity.HIGH: "#d1451b",
    Severity.MEDIUM: "#b7791f",
    Severity.LOW: "#2b6cb0",
    Severity.INFO: "#718096",
}

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  margin: 0; background: #0b0d12; color: #e6e8eb; line-height: 1.5; }
.wrap { max-width: 960px; margin: 0 auto; padding: 40px 24px 80px; }
header h1 { font-size: 22px; margin: 0 0 4px; font-weight: 650; }
header .target { color: #9aa4b2; font-size: 14px; word-break: break-all; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 20px; margin: 16px 0 28px; color: #9aa4b2; font-size: 13px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0 28px; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; border-radius: 999px;
  font-size: 12px; font-weight: 600; color: #fff; }
.card { background: #12151c; border: 1px solid #1e2530; border-radius: 12px; padding: 18px 20px; margin: 14px 0; }
.card h3 { margin: 0 0 10px; font-size: 16px; font-weight: 620; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 700;
  color: #fff; margin-right: 8px; vertical-align: middle; }
.kv { color: #9aa4b2; font-size: 13px; margin: 2px 0; }
.kv b { color: #cbd3dd; font-weight: 600; }
pre { background: #0b0d12; border: 1px solid #1e2530; border-radius: 8px; padding: 12px;
  overflow-x: auto; font-size: 12.5px; color: #cbd3dd; white-space: pre-wrap; word-break: break-word; }
.section-title { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: #7c8798;
  margin: 14px 0 4px; }
a { color: #6ea8fe; }
.footer { margin-top: 40px; color: #66707e; font-size: 12px; }
.empty { color: #9aa4b2; }
"""


def _chip(severity: Severity, count: int) -> str:
    color = _SEVERITY_COLOR[severity]
    label = _SEVERITY_LABEL[severity]
    return f'<span class="chip" style="background:{color}">{label}: {count}</span>'


def _finding_card(index: int, finding: Finding) -> str:
    color = _SEVERITY_COLOR[finding.severity]
    parts: list[str] = []
    parts.append('<div class="card">')
    parts.append(
        f'<h3><span class="badge" style="background:{color}">'
        f"{_SEVERITY_LABEL[finding.severity]}</span>{index}. {escape(finding.title)}</h3>"
    )
    parts.append(f'<div class="kv"><b>Confidence:</b> {escape(finding.confidence.value)} '
                 f"&nbsp;·&nbsp; <b>Priority:</b> {priority_score(finding)}/100</div>")
    parts.append(f'<div class="kv"><b>Category:</b> {escape(finding.category)}</div>')
    if finding.cwe or finding.owasp:
        cwe = escape(finding.cwe or "-")
        owasp = escape(finding.owasp or "-")
        parts.append(f'<div class="kv"><b>CWE:</b> {cwe} &nbsp;·&nbsp; <b>OWASP:</b> {owasp}</div>')
    endpoint = f"{escape(finding.method)} {escape(finding.endpoint)}"
    parts.append(f'<div class="kv"><b>Endpoint:</b> {endpoint}</div>')
    if finding.parameter:
        parts.append(f'<div class="kv"><b>Parameter:</b> {escape(finding.parameter)}</div>')

    parts.append('<div class="section-title">Impact</div>')
    parts.append(f"<div>{escape(finding.impact)}</div>")

    parts.append('<div class="section-title">Evidence</div>')
    parts.append(f"<div>{escape(finding.evidence.summary)}</div>")
    if finding.evidence.response:
        parts.append(f"<pre>{escape(finding.evidence.response)}</pre>")

    parts.append('<div class="section-title">Recommendation</div>')
    parts.append(f"<div>{escape(finding.recommendation)}</div>")
    if finding.remediation_example:
        parts.append(f"<pre>{escape(finding.remediation_example)}</pre>")

    if finding.references:
        refs = "".join(
            f'<li><a href="{escape(ref)}" rel="noreferrer noopener">{escape(ref)}</a></li>'
            for ref in finding.references
        )
        parts.append('<div class="section-title">References</div>')
        parts.append(f"<ul>{refs}</ul>")

    parts.append("</div>")
    return "".join(parts)


def to_html(result: ScanResult) -> str:
    counts = result.stats.by_severity
    chips = "".join(
        _chip(sev, counts.get(sev.value, 0)) for sev in _SEVERITY_ORDER if counts.get(sev.value, 0)
    )
    if not chips:
        chips = '<span class="chip" style="background:#2f855a">No findings</span>'

    cards = (
        "".join(_finding_card(i, f) for i, f in enumerate(result.findings, start=1))
        if result.findings
        else '<p class="empty">No findings within the authorised scope.</p>'
    )

    duration = "n/a"
    if result.finished_at:
        duration = f"{(result.finished_at - result.started_at).total_seconds():.1f}s"

    auth = "authenticated" if result.authenticated else "unauthenticated"
    techs = ", ".join(
        f"{t.name}{f' {t.version}' if t.version else ''}" for t in result.technologies
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>IsaHat Report — {escape(result.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>IsaHat Security Audit</h1>
    <div class="target">{escape(result.target)}</div>
  </header>
  <div class="meta">
    <span>Scan <b>{escape(result.id)}</b></span>
    <span>Profile: {escape(result.profile)} ({auth})</span>
    <span>Started: {escape(result.started_at.isoformat())}</span>
    <span>Duration: {escape(duration)}</span>
    <span>Endpoints: {result.stats.endpoints_discovered}</span>
    <span>Forms: {result.stats.forms_discovered}</span>
    <span>Requests: {result.stats.requests_made}</span>
    <span>IsaHat {escape(__version__)}</span>
  </div>
  <div class="chips">{chips}</div>
  {f'<div class="kv"><b>Technologies:</b> {escape(techs)}</div>' if techs else ''}
  <h2>Findings</h2>
  {cards}
  <div class="footer">
    Generated by IsaHat. Authorised use only — see the project's Responsible Use policy.
    Severity and confidence are reported separately; review confidence before acting.
  </div>
</div>
</body>
</html>
"""
