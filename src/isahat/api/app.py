"""The FastAPI application exposing the shared engine over local HTTP.

Design notes:

* **Same engine, no duplication.** Every operation goes through
  :class:`~isahat.core.engine.ScanEngine`, ``ScanStore`` and the reporters —
  nothing is re-implemented for the GUI.
* **Loopback-only by default.** ``isahat serve`` binds to 127.0.0.1 and scans
  still require explicit scope confirmation server-side (the desktop app sends
  ``confirmed: true`` after showing the same authorisation banner as the CLI).
* **Live progress.** Scans run as asyncio tasks; progress events are buffered
  per scan and streamed to clients over SSE (``/scans/{id}/events``).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from isahat import __version__
from isahat.core.auth import AuthConfig
from isahat.core.config import load_config
from isahat.core.engine import ScanEngine
from isahat.core.models import FindingAnnotation, FindingState, ScanResult, Severity
from isahat.core.scope import ScopeViolation
from isahat.reporting import compare_scans, extension_for, render
from isahat.reporting.compare import diff_to_markdown
from isahat.storage import ScanStore

_EVENT_BUFFER_LIMIT = 500


class ScanRequest(BaseModel):
    """Payload for starting a scan through the bridge."""

    target: str
    profile: str = "safe"
    scan_type: str = "web"
    auth: AuthConfig | None = None
    rate_limit_check: bool = False
    confirmed: bool = False  # the client showed the authorisation banner


class ScanAccepted(BaseModel):
    scan_id: str
    target: str


class AnnotationRequest(BaseModel):
    state: FindingState
    comment: str | None = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str  # running | done | error
    detail: str = ""
    events: list[dict[str, Any]] = Field(default_factory=list)


class _ScanJob:
    """A running (or finished) scan and its progress event buffer."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.events: list[dict[str, Any]] = []
        self.status = "running"
        self.detail = ""
        self.task: asyncio.Task[None] | None = None
        self.condition = asyncio.Condition()

    async def publish(self, stage: str, message: str) -> None:
        self.events.append({"stage": stage, "message": message})
        if len(self.events) > _EVENT_BUFFER_LIMIT:
            del self.events[: len(self.events) - _EVENT_BUFFER_LIMIT]
        async with self.condition:
            self.condition.notify_all()


def create_app(
    db_path: str | Path | None = None,
    *,
    config_path: str | Path | None = None,
) -> FastAPI:
    """Build the bridge application. ``db_path`` is injectable for tests."""

    app = FastAPI(title="IsaHat Bridge", version=__version__)
    # The desktop webview (Tauri) calls the bridge cross-origin. Only the
    # local app origins are allowed — the bridge is loopback-only anyway.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^(https?://(localhost|127\.0\.0\.1)(:\d+)?|tauri://localhost)$",
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    store = ScanStore(db_path)
    base_config = load_config(config_path)
    jobs: dict[str, _ScanJob] = {}

    async def _run_scan(job: _ScanJob, request: ScanRequest) -> None:
        config = base_config.model_copy(deep=True)
        config.scan.profile = request.profile
        # The bridge is invoked programmatically; the explicit `confirmed` flag
        # in the payload replaces the interactive prompt.
        config.safety.require_scope_confirmation = False
        config.safety.rate_limit_checks = request.rate_limit_check

        def on_progress(stage: str, message: str) -> None:
            # Called from within the engine's async context, so a loop exists.
            asyncio.get_running_loop().create_task(job.publish(stage, message))

        engine = ScanEngine(
            request.target,
            config,
            scan_type=request.scan_type,
            on_progress=on_progress,
            auth=request.auth,
            checkpoint_store=store,
            scan_id=job.scan_id,
        )
        try:
            result = await engine.run()
        except ScopeViolation as exc:
            job.status, job.detail = "error", f"scope: {exc}"
        except Exception as exc:  # noqa: BLE001 - surface as job status, not a crash
            job.status, job.detail = "error", str(exc)
        else:
            store.save(result)
            job.status, job.detail = "done", result.id
        async with job.condition:
            job.condition.notify_all()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/scans", status_code=202)
    async def start_scan(request: ScanRequest) -> ScanAccepted:
        if not request.confirmed:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Scope authorisation not confirmed. The client must display the "
                    "authorisation banner and resend with confirmed=true."
                ),
            )
        scan_id = uuid.uuid4().hex[:12]
        job = _ScanJob(scan_id)
        jobs[scan_id] = job
        await job.publish("queued", f"scan queued for {request.target}")
        job.task = asyncio.create_task(_run_scan(job, request))
        return ScanAccepted(scan_id=scan_id, target=request.target)

    @app.get("/scans")
    def list_scans(limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict[str, Any]]:
        rows = store.list(limit=limit)
        return [
            {
                "id": row.id,
                "target": row.target,
                "profile": row.profile,
                "started_at": row.started_at,
                "finished_at": row.finished_at,
                "findings_total": row.findings_total,
                "by_severity": {
                    "critical": row.critical,
                    "high": row.high,
                    "medium": row.medium,
                    "low": row.low,
                    "info": row.info,
                },
                "running": row.id in jobs and jobs[row.id].status == "running",
            }
            for row in rows
        ]

    @app.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> ScanResult:
        result = store.get(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")
        return store.apply_annotations(result)

    @app.get("/scans/{scan_id}/status")
    async def scan_status(scan_id: str) -> ScanStatus:
        job = jobs.get(scan_id)
        if job is None:
            result = store.get(scan_id)
            if result is None:
                raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")
            return ScanStatus(scan_id=scan_id, status="done", detail=result.id)
        return ScanStatus(
            scan_id=scan_id, status=job.status, detail=job.detail, events=job.events
        )

    @app.get("/scans/{scan_id}/events")
    async def scan_events(scan_id: str) -> StreamingResponse:
        job = jobs.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")

        async def stream() -> AsyncIterator[str]:
            cursor = 0
            while True:
                while cursor < len(job.events):
                    event = job.events[cursor]
                    cursor += 1
                    yield f"data: {json.dumps(event)}\n\n"
                if job.status != "running":
                    yield f"data: {json.dumps({'stage': job.status, 'message': job.detail})}\n\n"
                    return
                async with job.condition:
                    await job.condition.wait()

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/scans/{scan_id}/report")
    def scan_report(scan_id: str, fmt: str = "markdown") -> PlainTextResponse:
        result = store.get(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")
        result = store.apply_annotations(result)
        try:
            content = render(result, fmt)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        filename = f"isahat-{scan_id}.{extension_for(fmt)}"
        return PlainTextResponse(
            content,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/scans/{scan_id}/findings/{finding_id}/annotation")
    def annotate(scan_id: str, finding_id: str, request: AnnotationRequest) -> dict[str, str]:
        result = store.get(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")
        if not any(f.id == finding_id for f in result.findings):
            raise HTTPException(
                status_code=404, detail=f"finding not in scan {scan_id}: {finding_id}"
            )
        store.set_annotation(
            FindingAnnotation(
                finding_id=finding_id, state=request.state, comment=request.comment
            )
        )
        return {"status": "ok", "finding_id": finding_id, "state": request.state.value}

    @app.get("/compare")
    def compare(base: str, head: str) -> dict[str, Any]:
        base_raw = store.get(base)
        head_raw = store.get(head)
        if base_raw is None or head_raw is None:
            missing = base if base_raw is None else head
            raise HTTPException(status_code=404, detail=f"scan not found: {missing}")
        base_result = store.apply_annotations(base_raw)
        head_result = store.apply_annotations(head_raw)
        diff = compare_scans(base_result, head_result)
        return {
            "base": base,
            "head": head,
            "new": [f.id for f in diff.new],
            "resolved": [f.id for f in diff.resolved],
            "unchanged": [f.id for f in diff.unchanged],
            "markdown": diff_to_markdown(diff),
        }

    @app.get("/severities")
    def severities() -> list[str]:
        return [s.value for s in Severity]

    return app
