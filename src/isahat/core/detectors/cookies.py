"""Detects insecure cookie attributes (missing Secure/HttpOnly/SameSite).

Passive: inspects Set-Cookie headers already captured. Cookie values are never
stored — only the attribute analysis and the cookie name are reported.
"""

from __future__ import annotations

from http.cookies import SimpleCookie

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity


class CookieSecurityDetector(Detector):
    name = "cookie-security"
    category = "Session Management"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for response in ctx.responses:
            raw = response.headers.get("set-cookie")
            if not raw:
                continue
            is_https = response.url.lower().startswith("https://")
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:  # noqa: BLE001 - malformed Set-Cookie must not abort
                continue

            for name, morsel in cookie.items():
                problems: list[str] = []
                if is_https and not morsel["secure"]:
                    problems.append("missing Secure flag on an HTTPS site")
                if not morsel["httponly"]:
                    problems.append("missing HttpOnly flag")
                samesite = str(morsel["samesite"]).strip().lower()
                if not samesite:
                    problems.append("missing SameSite attribute")

                if not problems:
                    continue
                key = (response.url, name)
                if key in seen:
                    continue
                seen.add(key)

                severity = Severity.MEDIUM if any("Secure" in p for p in problems) else Severity.LOW
                findings.append(
                    Finding(
                        title=f"Insecure cookie attributes on '{name}'",
                        category=self.category,
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        cwe="CWE-614",
                        owasp="A05:2021 Security Misconfiguration",
                        endpoint=response.url,
                        method=response.request_method,
                        parameter=name,
                        evidence=Evidence(
                            summary=f"Cookie '{name}' set with: " + "; ".join(problems),
                            response=f"Set-Cookie: {name}=***REDACTED*** ("
                            + ", ".join(problems)
                            + ")",
                            location="Set-Cookie",
                        ),
                        impact=(
                            "Cookies without HttpOnly are readable by JavaScript (XSS theft); "
                            "without Secure they can leak over HTTP; without SameSite they are "
                            "exposed to CSRF."
                        ),
                        likelihood="medium",
                        exploitation="Combined with XSS or CSRF to hijack the session.",
                        recommendation=(
                            "Set Secure, HttpOnly and an explicit SameSite (Lax or Strict) on "
                            "session and auth cookies."
                        ),
                        remediation_example="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax",
                        references=[
                            "https://owasp.org/www-community/controls/SecureCookieAttribute",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                        ],
                        false_positive_hints=[
                            "Non-session cookies (e.g. analytics) may intentionally omit HttpOnly.",
                        ],
                    )
                )
        return findings
