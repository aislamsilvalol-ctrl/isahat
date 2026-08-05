"""Detects reflected XSS with a unique, benign marker payload.

The payload is a harmless marker containing HTML-significant characters. If the
server reflects it **unencoded** into an HTML response, the value is not being
escaped and reflected XSS is likely. No script is ever executed — IsaHat only
checks whether the raw characters survive.
"""

from __future__ import annotations

import secrets

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.sanitize import truncate

_MAX_POINTS = 20


class ReflectedXssDetector(Detector):
    name = "reflected-xss"
    category = "Cross-Site Scripting"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for point in ctx.injection_points[:_MAX_POINTS]:
            token = "isahat" + secrets.token_hex(4)
            # HTML-significant characters that must be encoded if handled safely.
            payload = f'{token}<svg/onload>"\''
            test_url = point.build_url(payload)
            try:
                response = await ctx.client.get(test_url)
            except Exception:  # noqa: BLE001 - probing errors are not findings
                continue

            content_type = (response.headers.get("content-type") or "").lower()
            if "html" not in content_type:
                continue
            # Reported only if the raw, unencoded payload is reflected verbatim.
            if payload not in response.text:
                continue

            finding = Finding(
                title="Reflected input without output encoding (possible XSS)",
                category=self.category,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe="CWE-79",
                owasp="A03:2021 Injection",
                endpoint=point.url,
                method="GET",
                parameter=point.param,
                evidence=Evidence(
                    summary=(
                        f"Parameter '{point.param}' was reflected unencoded into the HTML "
                        "response, including '<', '>' and quote characters."
                    ),
                    request=f"GET {test_url}",
                    response=truncate(self._snippet(response.text, payload)),
                    location=point.param,
                ),
                impact=(
                    "Unencoded reflection allows script injection in the victim's browser, "
                    "enabling session theft, defacement and actions on the user's behalf."
                ),
                likelihood="high",
                exploitation="Deliver a crafted URL; the injected markup renders in the browser.",
                recommendation=(
                    "Context-aware output encoding for all user input rendered into HTML; "
                    "prefer framework auto-escaping and a strict Content-Security-Policy."
                ),
                remediation_example=(
                    "# Escape before rendering\n"
                    "from markupsafe import escape\n"
                    "html = f'<p>{escape(user_input)}</p>'"
                ),
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
                false_positive_hints=[
                    "Confirm the reflection is in an executable HTML context, not inside a "
                    "text node that a CSP or framework neutralises.",
                ],
            )
            if finding.id not in seen:
                seen.add(finding.id)
                findings.append(finding)
        return findings

    def _snippet(self, body: str, needle: str) -> str:
        idx = body.find(needle)
        if idx == -1:
            return needle
        start = max(0, idx - 60)
        end = min(len(body), idx + len(needle) + 60)
        return body[start:end]
