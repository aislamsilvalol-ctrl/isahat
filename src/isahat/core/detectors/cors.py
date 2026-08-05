"""Detects insecure CORS configurations with a controlled Origin probe.

Active but non-destructive: sends GET requests with a crafted ``Origin`` header
and inspects the ``Access-Control-Allow-Origin`` / ``-Allow-Credentials``
response. Reflecting an arbitrary origin (especially with credentials) lets a
malicious site read authenticated responses.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.http import HttpResponse
from isahat.core.models import Confidence, Evidence, Finding, Severity

_PROBE_ORIGIN = "https://isahat-cors-probe.example"
_MAX_PROBES = 6


class CorsDetector(Detector):
    name = "cors"
    category = "Security Misconfiguration"

    def _probe_urls(self, ctx: DetectorContext) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for response in ctx.responses:
            parsed = urlparse(response.url)
            base = urlunparse(parsed._replace(query="", fragment=""))
            if base in seen:
                continue
            seen.add(base)
            urls.append(base)
            if len(urls) >= _MAX_PROBES:
                break
        return urls

    def _evaluate(self, url: str, response: HttpResponse) -> Finding | None:
        headers = response.headers
        acao = headers.get("access-control-allow-origin")
        if not acao:
            return None
        acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
        credentials = acac == "true"

        reflects_probe = acao.strip() == _PROBE_ORIGIN
        wildcard = acao.strip() == "*"
        if not (reflects_probe or wildcard):
            return None

        if reflects_probe and credentials:
            severity = Severity.HIGH
            confidence = Confidence.CONFIRMED
            detail = "reflects an arbitrary Origin and allows credentials"
        elif reflects_probe:
            severity = Severity.MEDIUM
            confidence = Confidence.CONFIRMED
            detail = "reflects an arbitrary Origin"
        elif wildcard and credentials:
            severity = Severity.MEDIUM
            confidence = Confidence.HIGH
            detail = "uses '*' together with credentials (invalid and unsafe)"
        else:
            severity = Severity.LOW
            confidence = Confidence.HIGH
            detail = "uses a wildcard '*' Access-Control-Allow-Origin"

        return Finding(
            title=f"Insecure CORS policy ({detail})",
            category=self.category,
            severity=severity,
            confidence=confidence,
            cwe="CWE-942",
            owasp="A05:2021 Security Misconfiguration",
            endpoint=url,
            method="GET",
            evidence=Evidence(
                summary=(
                    f"With Origin: {_PROBE_ORIGIN}, the server responded "
                    f"Access-Control-Allow-Origin: {acao}"
                    + (f", Access-Control-Allow-Credentials: {acac}" if acac else "")
                ),
                response=(
                    f"Access-Control-Allow-Origin: {acao}\n"
                    + (f"Access-Control-Allow-Credentials: {acac}" if acac else "")
                ),
                location="Access-Control-Allow-Origin",
            ),
            impact=(
                "A permissive CORS policy can let malicious web pages read responses "
                "on behalf of a logged-in user, exposing their data."
            ),
            likelihood="medium",
            exploitation="A malicious origin issues cross-site requests and reads the response.",
            recommendation=(
                "Reflect only an explicit allowlist of trusted origins; never combine "
                "credentials with a reflected or wildcard origin."
            ),
            remediation_example=(
                "Access-Control-Allow-Origin: https://app.example.com\n"
                "Access-Control-Allow-Credentials: true  # only for allowlisted origins"
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                "https://portswigger.net/web-security/cors",
            ],
            false_positive_hints=[
                "A wildcard on a genuinely public, unauthenticated API may be intentional.",
            ],
        )

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for url in self._probe_urls(ctx):
            try:
                response = await ctx.client.get(url, headers={"Origin": _PROBE_ORIGIN})
            except Exception:  # noqa: BLE001 - probing errors are not findings
                continue
            finding = self._evaluate(url, response)
            if finding and finding.id not in seen:
                seen.add(finding.id)
                findings.append(finding)
        return findings
