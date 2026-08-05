"""Checkpointing of in-progress scans so interrupted audits can resume.

The engine saves a checkpoint after each stage (crawl, API discovery, each
detector). If a scan is interrupted, ``isahat scan --resume <scan-id>`` reloads
the checkpoint and continues from the first unfinished stage instead of
starting over. Completed scans delete their checkpoint.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field

from isahat.core.http import HttpResponse
from isahat.core.models import ApiSpec, DiscoveredForm, Endpoint, Finding

# Stage progression: crawl -> apis -> detectors -> done.
STAGE_CRAWL = "crawl"
STAGE_APIS = "apis"
STAGE_DETECTORS = "detectors"


class ResponseSnapshot(BaseModel):
    """Serializable form of an ``HttpResponse`` for checkpointing."""

    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    request_method: str
    request_headers: dict[str, str]

    @classmethod
    def from_response(cls, response: HttpResponse) -> ResponseSnapshot:
        return cls(
            url=response.url,
            status=response.status,
            headers=dict(response.headers),
            text=response.text,
            elapsed_ms=response.elapsed_ms,
            request_method=response.request_method,
            request_headers=dict(response.request_headers),
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
