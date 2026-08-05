"""Masking of sensitive data before it is ever stored or reported.

IsaHat must never persist raw secrets. This module centralises the redaction
logic so evidence, requests and responses are consistently sanitised.
"""

from __future__ import annotations

import re

_MASK = "***REDACTED***"

# Header names whose values are always masked.
_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "api-key",
}

# Patterns for secrets that can appear inside bodies or free text.
_SECRET_PATTERNS = [
    # Bearer tokens
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    # JWT (three base64url segments)
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    # AWS access key id
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Generic "key": "value" / key=value pairs for common secret names. The key
    # may carry a suffix (password_hash, access_token, ...) — over-masking is
    # the safe direction for a redaction function.
    re.compile(
        r"(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[\w-]*)"
        r"([\"']?\s*[:=]\s*[\"']?)([^\s\"',}&]+)"
    ),
]


def mask_value(value: str) -> str:
    """Redact any secrets found inside a free-form string."""

    masked = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            masked = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{_MASK}", masked)
        else:
            masked = pattern.sub(_MASK, masked)
    return masked


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive values redacted."""

    result: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _SENSITIVE_HEADERS:
            result[name] = _MASK
        else:
            result[name] = mask_value(value)
    return result


def format_headers(headers: dict[str, str]) -> str:
    masked = mask_headers(headers)
    return "\n".join(f"{name}: {value}" for name, value in masked.items())


def truncate(text: str, limit: int = 2000) -> str:
    """Cap stored evidence so reports stay readable and files stay small."""

    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"
