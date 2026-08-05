"""Detects open redirects via a controlled, non-following probe.

For GET parameters (prioritising redirect-like names), IsaHat sets the value to
a sentinel external URL and requests **without following redirects**. If the
server responds with a 3xx whose ``Location`` points to the sentinel host, the
redirect target is attacker-controllable.
"""

from __future__ import annotations

from urllib.parse import urlparse

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.injection import InjectionPoint
from isahat.core.models import Confidence, Evidence, Finding, Severity

_SENTINEL_HOST = "isahat-redirect.example"
_SENTINEL_URL = f"https://{_SENTINEL_HOST}/probe"
_MAX_POINTS = 15

_REDIRECT_PARAM_NAMES = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_to", "returnto", "dest", "destination", "continue", "r", "u", "to",
    "goto", "link", "out", "target", "forward", "callback",
}


class OpenRedirectDetector(Detector):
    name = "open-redirect"
    category = "Open Redirect"

    def _select_points(self, ctx: DetectorContext) -> list[InjectionPoint]:
        redirecty = [p for p in ctx.injection_points if p.param.lower() in _REDIRECT_PARAM_NAMES]
        chosen = redirecty or ctx.injection_points[:5]
        return chosen[:_MAX_POINTS]

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for point in self._select_points(ctx):
            test_url = point.build_url(_SENTINEL_URL)
            try:
                response = await ctx.client.get(test_url, follow_redirects=False)
            except Exception:  # noqa: BLE001 - probing errors are not findings
                continue
            if not 300 <= response.status < 400:
                continue
            location = response.headers.get("location", "")
            if urlparse(location).hostname != _SENTINEL_HOST:
                continue

            finding = Finding(
                title="Open redirect via user-controlled parameter",
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe="CWE-601",
                owasp="A01:2021 Broken Access Control",
                endpoint=point.url,
                method="GET",
                parameter=point.param,
                evidence=Evidence(
                    summary=(
                        f"Setting '{point.param}' to {_SENTINEL_URL} produced an HTTP "
                        f"{response.status} redirect to that external host."
                    ),
                    request=f"GET {test_url}",
                    response=f"HTTP {response.status}\nLocation: {location}",
                    location=point.param,
                ),
                impact=(
                    "Attackers can craft links on your domain that redirect victims to "
                    "malicious sites, aiding phishing and OAuth token theft."
                ),
                likelihood="medium",
                exploitation="Send a victim a trusted-looking link that redirects off-site.",
                recommendation=(
                    "Do not redirect to user-supplied absolute URLs. Allowlist paths or "
                    "validate the target against a fixed set of trusted destinations."
                ),
                remediation_example=(
                    "# Only allow relative paths\n"
                    "if not target.startswith('/') or target.startswith('//'):\n"
                    "    target = '/'"
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                ],
            )
            if finding.id not in seen:
                seen.add(finding.id)
                findings.append(finding)
        return findings
