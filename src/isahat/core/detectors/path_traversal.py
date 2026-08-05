"""Detects path traversal / local file inclusion with read-only probes.

For GET parameters (prioritising file-like names), IsaHat requests a handful of
traversal payloads targeting well-known files and looks for their signature
content in the response. This only *reads*; it never writes or deletes. A
strong signature (e.g. an ``/etc/passwd`` line) yields high confidence.
"""

from __future__ import annotations

import re

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.injection import InjectionPoint
from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.sanitize import truncate

_MAX_POINTS = 12

# Payloads target classic files via relative traversal, absolute paths and a
# common encoding-bypass. Kept short to bound request volume.
_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
]

_SIGNATURES = [
    re.compile(r"root:.*:0:0:", re.MULTILINE),  # /etc/passwd
    re.compile(r"\[extensions\]", re.IGNORECASE),  # win.ini
    re.compile(r"for 16-bit app support", re.IGNORECASE),  # win.ini
]

_FILE_PARAM_NAMES = {
    "file", "path", "page", "template", "doc", "document", "download", "filename",
    "dir", "folder", "include", "inc", "load", "view", "name", "resource", "item",
}


def _matched_signature(body: str) -> str | None:
    for pattern in _SIGNATURES:
        match = pattern.search(body)
        if match:
            return match.group(0)[:80]
    return None


class PathTraversalDetector(Detector):
    name = "path-traversal"
    category = "Path Traversal"

    def _select_points(self, ctx: DetectorContext) -> list[InjectionPoint]:
        filey = [p for p in ctx.injection_points if p.param.lower() in _FILE_PARAM_NAMES]
        chosen = filey or ctx.injection_points[:5]
        return chosen[:_MAX_POINTS]

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for point in self._select_points(ctx):
            for payload in _PAYLOADS:
                test_url = point.build_url(payload)
                try:
                    response = await ctx.client.get(test_url)
                except Exception:  # noqa: BLE001 - probing errors are not findings
                    continue
                signature = _matched_signature(response.text)
                if signature is None:
                    continue

                finding = Finding(
                    title="Path traversal / local file inclusion",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-22",
                    owasp="A01:2021 Broken Access Control",
                    endpoint=point.url,
                    method="GET",
                    parameter=point.param,
                    evidence=Evidence(
                        summary=(
                            f"Parameter '{point.param}' returned system file content when set "
                            f"to a traversal payload (signature: {signature!r})."
                        ),
                        request=f"GET {test_url}",
                        response=truncate(response.text, 500),
                        location=point.param,
                    ),
                    impact=(
                        "Reading arbitrary files can expose source code, credentials and "
                        "configuration; in some stacks it escalates to code execution."
                    ),
                    likelihood="high",
                    exploitation="A crafted parameter value escapes the intended directory.",
                    recommendation=(
                        "Never build filesystem paths from user input. Resolve against a fixed "
                        "base directory and reject any path that escapes it; prefer opaque IDs."
                    ),
                    remediation_example=(
                        "base = Path('/var/app/files').resolve()\n"
                        "target = (base / user_name).resolve()\n"
                        "if base not in target.parents:\n"
                        "    raise PermissionError('path outside base')"
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Path_Traversal",
                        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                    ],
                    false_positive_hints=[
                        "Confirm the content is a real system file and not a crafted error page.",
                    ],
                )
                if finding.id not in seen:
                    seen.add(finding.id)
                    findings.append(finding)
                break  # one confirmed payload per point is enough
        return findings
