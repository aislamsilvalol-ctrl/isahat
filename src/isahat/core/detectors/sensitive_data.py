"""Detects excessive data exposure in API/JSON responses (passive).

Scans JSON bodies already fetched by the crawler for keys that usually indicate
sensitive data (passwords, secrets, tokens, IDs like SSN/CNPJ, card numbers).
Values are always masked in evidence. Confidence stays at *probable*: only a
human can confirm the value is real and the field shouldn't be returned — the
classic "excessive data exposure" pattern in APIs.
"""

from __future__ import annotations

import json
from typing import Any

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.sanitize import mask_value, truncate

# key substring -> (human label, severity)
_SENSITIVE_KEYS: dict[str, tuple[str, Severity]] = {
    "password": ("password", Severity.HIGH),
    "passwd": ("password", Severity.HIGH),
    "secret": ("secret", Severity.HIGH),
    "private_key": ("private key", Severity.HIGH),
    "ssn": ("SSN", Severity.HIGH),
    "credit_card": ("credit card", Severity.HIGH),
    "card_number": ("card number", Severity.HIGH),
    "cvv": ("card CVV", Severity.HIGH),
    "token": ("token", Severity.MEDIUM),
    "api_key": ("API key", Severity.MEDIUM),
    "apikey": ("API key", Severity.MEDIUM),
    "cnpj": ("CNPJ", Severity.MEDIUM),
    "cpf": ("CPF", Severity.MEDIUM),
}

_MAX_BODY_BYTES = 200_000


def _iter_keys(node: Any, path: str = "") -> list[tuple[str, str]]:
    """Flatten a JSON document into (dotted key path, value-as-string) pairs."""

    pairs: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            pairs.extend(_iter_keys(value, child_path))
    elif isinstance(node, list):
        for index, value in enumerate(node[:5]):  # sample lists; enough for a signal
            pairs.extend(_iter_keys(value, f"{path}[{index}]"))
    else:
        pairs.append((path, str(node)))
    return pairs


class SensitiveDataExposureDetector(Detector):
    name = "sensitive-data-exposure"
    category = "API Security"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for response in ctx.responses:
            content_type = response.headers.get("content-type", "")
            if "json" not in content_type or len(response.text) > _MAX_BODY_BYTES:
                continue
            try:
                document = json.loads(response.text)
            except json.JSONDecodeError:
                continue

            hits: list[tuple[str, str, Severity]] = []  # (key path, label, severity)
            for key_path, value in _iter_keys(document):
                leaf = key_path.rsplit(".", 1)[-1].lower()
                leaf = leaf.split("[", 1)[0]
                for marker, (label, severity) in _SENSITIVE_KEYS.items():
                    if marker in leaf and value and value.lower() not in ("null", "none", ""):
                        hits.append((key_path, label, severity))
                        break

            if not hits:
                continue
            top_severity = max((s for _, _, s in hits), key=lambda s: s.rank)
            labels = sorted({label for _, label, _ in hits})
            key_paths = [kp for kp, _, _ in hits[:6]]

            finding = Finding(
                title=f"Sensitive data exposed in API response ({', '.join(labels)})",
                category=self.category,
                severity=top_severity,
                confidence=Confidence.PROBABLE,
                cwe="CWE-200",
                owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=response.url,
                method=response.request_method,
                evidence=Evidence(
                    summary=(
                        "JSON response contains sensitive-looking field(s): "
                        + ", ".join(f"`{kp}`" for kp in key_paths)
                        + "."
                    ),
                    response=truncate(mask_value(response.text), 800),
                    location=", ".join(key_paths),
                ),
                impact=(
                    "Returning sensitive fields (excessive data exposure) lets any caller read "
                    "data the UI never needed — passwords, tokens or personal identifiers — "
                    "and often combines with BOLA to expose other users' records."
                ),
                likelihood="medium",
                exploitation="Any client that can reach the endpoint receives the extra fields.",
                recommendation=(
                    "Return only the fields the client needs (response DTOs / serializers with an "
                    "explicit allowlist). Never serialise internal models directly."
                ),
                remediation_example=(
                    "# pydantic: an explicit output model, never the ORM entity\n"
                    "class UserOut(BaseModel):\n"
                    "    id: int\n"
                    "    email: str\n"
                    "    model_config = ConfigDict(from_attributes=True)"
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
                ],
                false_positive_hints=[
                    "The value may be a placeholder/hash — verify it is real, sensitive data.",
                    "The field may be intentionally public for this resource.",
                ],
            )
            if finding.id not in seen:
                seen.add(finding.id)
                findings.append(finding)
        return findings
