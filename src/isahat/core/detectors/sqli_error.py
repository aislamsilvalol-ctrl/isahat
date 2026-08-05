"""Error-based SQL injection detection with a single non-destructive probe.

IsaHat appends a single quote to a parameter and looks for database error
signatures in the response. This is read-only and non-destructive; it does not
attempt boolean/time-based extraction or any data modification. Because error
signatures can have other causes, confidence is capped at ``PROBABLE``.
"""

from __future__ import annotations

import re

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.sanitize import truncate

_MAX_POINTS = 20

# Signatures of database errors surfaced to the response body.
_SQL_ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s*mysqli?_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),
    re.compile(r"psql:.*ERROR", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQLite3?::|sqlite3\.OperationalError", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
    re.compile(r"near \".*\": syntax error", re.I),
]


def _matched_signature(body: str) -> str | None:
    for pattern in _SQL_ERROR_SIGNATURES:
        match = pattern.search(body)
        if match:
            return match.group(0)
    return None


class SqlInjectionErrorDetector(Detector):
    name = "sqli-error"
    category = "Injection"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for point in ctx.injection_points[:_MAX_POINTS]:
            base_value = dict(point.base_params).get(point.param) or "1"
            payload = f"{base_value}'"
            test_url = point.build_url(payload)
            try:
                response = await ctx.client.get(test_url)
            except Exception:  # noqa: BLE001 - probing errors are not findings
                continue
            signature = _matched_signature(response.text)
            if signature is None:
                continue

            finding = Finding(
                title="Possible SQL injection (database error surfaced)",
                category=self.category,
                severity=Severity.HIGH,
                confidence=Confidence.PROBABLE,
                cwe="CWE-89",
                owasp="A03:2021 Injection",
                endpoint=point.url,
                method="GET",
                parameter=point.param,
                evidence=Evidence(
                    summary=(
                        f"Appending a single quote to '{point.param}' triggered a database "
                        f"error signature: {signature!r}."
                    ),
                    request=f"GET {test_url}",
                    response=truncate(response.text, 600),
                    location=point.param,
                ),
                impact=(
                    "SQL injection can allow reading or modifying database contents and, in "
                    "some cases, full system compromise."
                ),
                likelihood="medium",
                exploitation="A crafted parameter alters the SQL query executed server-side.",
                recommendation=(
                    "Use parameterised queries / prepared statements for all database access; "
                    "never build SQL by string concatenation with user input."
                ),
                remediation_example=(
                    "# Parameterised query (safe)\n"
                    "cursor.execute('SELECT * FROM items WHERE id = %s', (item_id,))"
                ),
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
                false_positive_hints=[
                    "A database error can have other causes; confirm with a manual, "
                    "authorised test before treating this as exploitable.",
                ],
            )
            if finding.id not in seen:
                seen.add(finding.id)
                findings.append(finding)
        return findings
