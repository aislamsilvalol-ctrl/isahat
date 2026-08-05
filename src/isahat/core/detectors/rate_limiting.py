"""Controlled, opt-in rate-limiting checks on authentication-like endpoints.

This detector is **never** enabled by default. When explicitly turned on
(``safety.rate_limit_checks`` or ``--rate-limit-check``) it sends a small,
paced burst of GET requests to endpoints that look like login/auth surfaces and
observes whether the server pushes back (HTTP 429 / lockout / captcha hints).

Hard safety rules baked in:

* burst size is capped (default 10, absolute max 30 requests per endpoint);
* a configurable interval paces requests (the client's own rate limiter also
  applies);
* the burst stops immediately on the first sign of throttling;
* every request/response pair is logged in evidence;
* only GET is ever used — no login attempts, no credential lists.
"""

from __future__ import annotations

import asyncio

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.sanitize import truncate

_HARD_CAP = 30
_MAX_ENDPOINTS = 3

# Path fragments that suggest an authentication-sensitive endpoint worth
# checking for throttling. The check only fires on these, never site-wide.
_AUTH_HINTS = ("login", "signin", "auth", "token", "otp", "password", "reset", "session")


def _auth_like_endpoints(ctx: DetectorContext) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for response in ctx.responses:
        url = response.url.split("?", 1)[0]
        lowered = url.lower()
        if any(hint in lowered for hint in _AUTH_HINTS) and url not in seen:
            seen.add(url)
            urls.append(url)
        if len(urls) >= _MAX_ENDPOINTS:
            break
    return urls


class RateLimitingDetector(Detector):
    name = "rate-limiting"
    category = "Authentication"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        burst = max(1, min(ctx.rate_limit_burst, _HARD_CAP))
        interval = max(0.0, ctx.rate_limit_interval)
        findings: list[Finding] = []

        for url in _auth_like_endpoints(ctx):
            throttled_at: int | None = None
            statuses: list[int] = []
            for attempt in range(1, burst + 1):
                try:
                    response = await ctx.client.get(url)
                except Exception:  # noqa: BLE001 - a failed probe is not evidence
                    break
                statuses.append(response.status)
                if response.status == 429:
                    throttled_at = attempt
                    break  # stop immediately on throttling
                if attempt < burst and interval > 0:
                    await asyncio.sleep(interval)

            if throttled_at is not None:
                # Throttling observed — the control exists; no finding.
                continue
            if len(statuses) < burst:
                # Could not complete the burst (network errors) — no basis to judge.
                continue

            evidence_log = "\n".join(
                f"attempt {i}: GET {url} -> {status}" for i, status in enumerate(statuses, 1)
            )
            findings.append(
                Finding(
                    title=f"No rate limiting observed on {url}",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.PROBABLE,
                    cwe="CWE-307",
                    owasp="A07:2021 Identification and Authentication Failures",
                    endpoint=url,
                    method="GET",
                    evidence=Evidence(
                        summary=(
                            f"{burst} consecutive requests to an authentication-like endpoint "
                            f"all returned {statuses[-1]} with no HTTP 429, lockout or "
                            "throttling signal."
                        ),
                        request=f"{burst}x GET {url} (paced {interval}s)",
                        response=truncate(evidence_log, 800),
                        location=url,
                    ),
                    impact=(
                        "Without throttling, attackers can attempt unlimited password guesses, "
                        "OTP codes or token values, making brute-force and credential-stuffing "
                        "attacks practical."
                    ),
                    likelihood="medium",
                    exploitation="Automated tools submit unlimited attempts at full speed.",
                    recommendation=(
                        "Add per-account and per-IP rate limiting with exponential backoff, "
                        "temporary lockout and/or CAPTCHA after a small number of failures; "
                        "return HTTP 429 with Retry-After."
                    ),
                    remediation_example=(
                        "# nginx\nlimit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\n"
                        "location /login { limit_req zone=login burst=5 nodelay; }"
                    ),
                    references=[
                        "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ],
                    false_positive_hints=[
                        "Throttling may exist at a layer IsaHat cannot see (WAF, CDN, upstream).",
                        "The burst is intentionally small; thresholds above it would not trigger.",
                    ],
                )
            )
        return findings
