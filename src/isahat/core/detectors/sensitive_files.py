"""Checks a short allowlist of commonly-exposed sensitive paths.

This detector is *active* but strictly non-destructive: it issues scoped GET
requests for a small, well-known set of paths (version control metadata, env
files, backups). Each candidate is validated with a content signature to keep
false positives low — a 200 that returns the site's HTML is not a match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.sanitize import mask_value, truncate


@dataclass(frozen=True)
class _Candidate:
    """A single sensitive path to probe, with the signals that confirm a hit."""

    path: str
    title: str
    severity: Severity
    cwe: str
    impact: str
    recommendation: str
    signatures: tuple[str, ...] = field(default_factory=tuple)
    requires_kv: bool = False


_CANDIDATES: tuple[_Candidate, ...] = (
    _Candidate(
        path="/.git/HEAD",
        title="Exposed Git repository metadata (.git/HEAD)",
        severity=Severity.HIGH,
        cwe="CWE-538",
        signatures=("ref:", "refs/heads/"),
        impact="A readable .git directory can leak full source code and secrets from history.",
        recommendation="Block access to .git/ at the web server/CDN and never deploy it.",
    ),
    _Candidate(
        path="/.env",
        title="Exposed environment file (.env)",
        severity=Severity.CRITICAL,
        cwe="CWE-215",
        signatures=("=", "\n"),
        requires_kv=True,
        impact="Environment files typically contain database credentials, API keys and secrets.",
        recommendation="Remove .env from the web root and rotate any exposed secrets.",
    ),
    _Candidate(
        path="/.env.local",
        title="Exposed environment file (.env.local)",
        severity=Severity.CRITICAL,
        cwe="CWE-215",
        signatures=("=",),
        requires_kv=True,
        impact="Local environment files often hold real credentials mistakenly deployed.",
        recommendation="Remove the file from the web root and rotate exposed secrets.",
    ),
    _Candidate(
        path="/.DS_Store",
        title="Exposed .DS_Store directory listing artefact",
        severity=Severity.LOW,
        cwe="CWE-548",
        signatures=("Bud1", "\x00"),
        impact="Leaks directory and file names, aiding further enumeration.",
        recommendation="Block .DS_Store files at the web server and remove them from deploys.",
    ),
    _Candidate(
        path="/backup.sql",
        title="Exposed database backup (backup.sql)",
        severity=Severity.CRITICAL,
        cwe="CWE-530",
        signatures=("INSERT INTO", "CREATE TABLE", "DROP TABLE"),
        impact="A downloadable SQL dump can expose the entire database contents.",
        recommendation="Remove backups from the web root; store them off the public server.",
    ),
)


def _looks_like_html(text: str) -> bool:
    head = text[:512].lower()
    return "<!doctype html" in head or "<html" in head


def _has_kv_line(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped and " " not in stripped.split("=", 1)[0]:
            return True
    return False


class SensitiveFilesDetector(Detector):
    name = "sensitive-files"
    category = "Sensitive Data Exposure"

    def _base_url(self, target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        base = self._base_url(ctx.target)

        for candidate in _CANDIDATES:
            url = urljoin(base + "/", candidate.path.lstrip("/"))
            if not ctx.scope.allows(url):
                continue
            try:
                response = await ctx.client.get(url)
            except Exception:  # noqa: BLE001 - probing errors are not findings
                continue
            if response.status != 200 or not response.text:
                continue

            body = response.text
            if _looks_like_html(body):
                # A 200 returning the app's HTML is almost always a SPA/router
                # fallback, not the real file. Skip to avoid a false positive.
                continue

            signatures = candidate.signatures
            matched = any(sig in body for sig in signatures) if signatures else True
            if candidate.requires_kv and not _has_kv_line(body):
                matched = False
            if not matched:
                continue

            confidence = Confidence.CONFIRMED if len(signatures) > 1 else Confidence.HIGH
            findings.append(
                Finding(
                    title=candidate.title,
                    category=self.category,
                    severity=candidate.severity,
                    confidence=confidence,
                    cwe=candidate.cwe,
                    owasp="A01:2021 Broken Access Control",
                    endpoint=url,
                    method="GET",
                    evidence=Evidence(
                        summary=f"HTTP 200 with matching content signature at {candidate.path}.",
                        response=truncate(mask_value(body), 800),
                        location=candidate.path,
                    ),
                    impact=candidate.impact,
                    likelihood="high",
                    exploitation="Directly downloadable via an unauthenticated GET request.",
                    recommendation=candidate.recommendation,
                    remediation_example=(
                        "Deny access to the path at the reverse proxy, e.g. nginx:\n"
                        f"location ~ {candidate.path} {{ deny all; return 404; }}"
                    ),
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    ],
                    false_positive_hints=[
                        "Confirm the content is the real file and not a custom error page.",
                    ],
                )
            )
        return findings
