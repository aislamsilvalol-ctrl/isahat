"""Detects missing or weak HTTP security headers and version disclosure.

This is a passive detector: it only inspects responses already captured by the
crawler. It reports on the target's primary HTML documents to avoid flooding a
report with one finding per asset.
"""

from __future__ import annotations

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.http import HttpResponse
from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.sanitize import format_headers, truncate

# header -> (title, severity, cwe, owasp, impact, recommendation)
_REQUIRED_HEADERS: dict[str, dict[str, str]] = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": Severity.MEDIUM.value,
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "impact": "Without a CSP, injected scripts run freely, amplifying the impact of XSS.",
        "recommendation": "Send a restrictive Content-Security-Policy (e.g. default-src 'self').",
        "example": "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    },
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "severity": Severity.MEDIUM.value,
        "cwe": "CWE-319",
        "owasp": "A05:2021 Security Misconfiguration",
        "impact": "Clients may connect over HTTP, exposing traffic to downgrade/MITM attacks.",
        "recommendation": "Send HSTS on HTTPS responses with a long max-age.",
        "example": "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": Severity.LOW.value,
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "impact": "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
        "recommendation": "Send X-Content-Type-Options: nosniff on all responses.",
        "example": "X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "title": "Missing anti-clickjacking protection",
        "severity": Severity.LOW.value,
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
        "impact": "The page can be framed by a malicious site, enabling clickjacking.",
        "recommendation": "Send X-Frame-Options: DENY or a CSP frame-ancestors directive.",
        "example": "X-Frame-Options: DENY",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "severity": Severity.INFO.value,
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "impact": "Full URLs (possibly with tokens) may leak to third parties via Referer.",
        "recommendation": "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
        "example": "Referrer-Policy: no-referrer",
    },
}

_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


class SecurityHeadersDetector(Detector):
    name = "security-headers"
    category = "Security Misconfiguration"

    def _pick_documents(self, ctx: DetectorContext) -> list[HttpResponse]:
        """Analyse HTML documents; if none, fall back to the first response."""

        docs = [
            r
            for r in ctx.responses
            if "html" in (r.headers.get("content-type") or "").lower()
        ]
        if docs:
            return docs[:1]  # the landing document is representative of app config
        return ctx.responses[:1]

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for response in self._pick_documents(ctx):
            lowered = {k.lower(): v for k, v in response.headers.items()}
            evidence_headers = format_headers(response.headers)

            for header, meta in _REQUIRED_HEADERS.items():
                if header in lowered:
                    continue
                findings.append(
                    Finding(
                        title=meta["title"],
                        category=self.category,
                        severity=Severity(meta["severity"]),
                        confidence=Confidence.CONFIRMED,
                        cwe=meta["cwe"],
                        owasp=meta["owasp"],
                        endpoint=response.url,
                        method=response.request_method,
                        evidence=Evidence(
                            summary=f"Response headers do not include '{header}'.",
                            response=truncate(evidence_headers),
                            location=header,
                        ),
                        impact=meta["impact"],
                        likelihood="medium",
                        exploitation="Depends on a companion issue (e.g. XSS) to be impactful.",
                        recommendation=meta["recommendation"],
                        remediation_example=meta["example"],
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                        ],
                    )
                )

            for header in _DISCLOSURE_HEADERS:
                value = lowered.get(header)
                if value and any(ch.isdigit() for ch in value):
                    findings.append(
                        Finding(
                            title=f"Software version disclosed via '{header}' header",
                            category="Information Disclosure",
                            severity=Severity.INFO,
                            confidence=Confidence.CONFIRMED,
                            cwe="CWE-200",
                            owasp="A05:2021 Security Misconfiguration",
                            endpoint=response.url,
                            method=response.request_method,
                            evidence=Evidence(
                                summary=f"{header}: {value}",
                                response=truncate(evidence_headers),
                                location=header,
                            ),
                            impact="Version banners help attackers match known CVEs to your stack.",
                            likelihood="low",
                            exploitation="Reconnaissance aid; not directly exploitable.",
                            recommendation="Suppress or genericise version information in responses.",
                            remediation_example=f"{header.title()}: (omit version)",
                            references=["https://owasp.org/www-project-secure-headers/"],
                        )
                    )
        return findings
