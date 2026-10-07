"""Checkpointing of in-progress scans so interrupted audits can resume.

The engine saves a checkpoint after each stage (crawl, API discovery, each
detector). If a scan is interrupted, ``isahat scan --resume <scan-id>`` reloads
the checkpoint and continues from the first unfinished stage instead of
starting over. A finished scan writes the ``ScanResult`` and deletes the
checkpoint in one store transaction.
"""

from __future__ import annotations

import hashlib
from typing import Protocol

from pydantic import BaseModel, Field

from isahat.core.http import HttpResponse
from isahat.core.models import ApiSpec, DiscoveredForm, Endpoint, Finding, ScanResult
from isahat.core.sanitize import mask_headers, mask_value, redact_set_cookie

# Resume feeds this text to tech fingerprinting and the sensitive-data
# detector, which itself ignores bodies larger than 200_000 characters.
_RESUME_BODY_CHARS = 200_000

# Stage progression: crawl -> apis -> detectors -> done.
STAGE_CRAWL = "crawl"
STAGE_APIS = "apis"
STAGE_DETECTORS = "detectors"


def _checkpoint_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact secrets. ``Set-Cookie`` keeps name and flags for resume."""

    masked = mask_headers(headers)
    for name, value in headers.items():
        if name.lower() == "set-cookie":
            masked[name] = redact_set_cookie(value)
    return masked


def _checkpoint_body(text: str) -> tuple[str, str, int]:
    """Return ``(masked text, sha256, byte size)`` for a response body.

    Hash and size describe the original payload. The masked, capped text is
    what resume reads; the raw body is not kept.
    """

    raw = text or ""
    encoded = raw.encode("utf-8", errors="replace")
    masked = mask_value(raw)
    if len(masked) > _RESUME_BODY_CHARS:
        masked = masked[:_RESUME_BODY_CHARS]
    return masked, hashlib.sha256(encoded).hexdigest(), len(encoded)


class ResponseSnapshot(BaseModel):
    """Serializable form of an ``HttpResponse`` for checkpointing.

    Resume rebuilds these into responses for technology fingerprinting and for
    detectors that have not finished, without fetching the pages again. A
    detector list that is already complete resumes with zero new requests.

    Stored headers have ``Authorization``, ``Cookie``, ``Proxy-Authorization``
    and API-key style values redacted. ``Set-Cookie`` keeps the cookie name and
    flags (``Secure``, ``HttpOnly``, ``SameSite``) so the cookie detector and
    cookie fingerprints still work; the cookie value is redacted.

    The raw body is not stored. ``body_sha256`` and ``body_size`` record the
    original payload. ``text`` is a masked copy capped at 200_000 characters —
    enough for HTML signatures and for JSON field names the sensitive-data
    detector reads. A hash alone would drop those checks on resume.
    """

    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    request_method: str
    request_headers: dict[str, str]
    body_sha256: str = ""
    body_size: int = 0

    @classmethod
    def from_response(cls, response: HttpResponse) -> ResponseSnapshot:
        text, digest, size = _checkpoint_body(response.text)
        return cls(
            url=response.url,
            status=response.status,
            headers=_checkpoint_headers(response.headers),
            text=text,
            body_sha256=digest,
            body_size=size,
            elapsed_ms=response.elapsed_ms,
            request_method=response.request_method,
            request_headers=_checkpoint_headers(response.request_headers),
        )

    def to_response(self) -> HttpResponse:
        return HttpResponse(
            url=self.url,
            status=self.status,
            headers=dict(self.headers),
            text=self.text,
            elapsed_ms=self.elapsed_ms,
            request_method=self.request_method,
            request_headers=dict(self.request_headers),
        )


class ScanCheckpoint(BaseModel):
    """Everything needed to resume an interrupted scan."""

    scan_id: str
    target: str
    stage: str = STAGE_CRAWL
    endpoints: list[Endpoint] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    responses: list[ResponseSnapshot] = Field(default_factory=list)
    apis: list[ApiSpec] = Field(default_factory=list)
    completed_detectors: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    requests_made: int = 0


class CheckpointStore(Protocol):
    """Persistence contract the engine needs (implemented by ``ScanStore``)."""

    def save_checkpoint(self, checkpoint: ScanCheckpoint) -> None: ...

    def load_checkpoint(self, scan_id: str) -> ScanCheckpoint | None: ...

    def delete_checkpoint(self, scan_id: str) -> None: ...

    def finalize_scan(self, result: ScanResult) -> None:
        """Store ``result`` and delete its checkpoint in a single transaction."""
        ...
