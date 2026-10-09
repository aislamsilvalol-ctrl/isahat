"""The FastAPI application exposing the shared engine over local HTTP.

Design notes:

* **Same engine, no duplication.** Every operation goes through
  :class:`~isahat.core.engine.ScanEngine`, ``ScanStore`` and the reporters —
  nothing is re-implemented for the GUI.
* **Loopback-only by default.** ``isahat serve`` binds to 127.0.0.1 and scans
  still require explicit scope confirmation server-side (the desktop app sends
  ``confirmed: true`` after showing the same authorisation banner as the CLI).
* **Local bearer token.** Every route except ``GET /health`` requires
  ``Authorization: Bearer`` matching the mode-0600 token file. The SSE route
  also accepts that token as a query parameter because ``EventSource`` cannot
  set headers. The query value is never logged.
* **Live progress.** Scans run as asyncio tasks; progress events are buffered
  per scan and streamed to clients over SSE (``/scans/{id}/events``).
  Each event carries an absolute id. A reconnect sends ``Last-Event-ID`` and
  receives only newer events. Finished jobs leave memory after a TTL.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Receive, Scope, Send

from isahat import __version__
from isahat.api.token import bridge_token_path, load_or_create_bridge_token
from isahat.core.auth import AuthConfig
from isahat.core.config import load_config
from isahat.core.engine import ScanEngine
from isahat.core.models import FindingAnnotation, FindingState, ScanResult, Severity
from isahat.core.scope import ScopeViolation
from isahat.core.state import ResumeRejected, require_resume_contract
from isahat.reporting import compare_scans, extension_for, render
from isahat.reporting.compare import diff_to_markdown
from isahat.storage import ScanStore

_EVENT_BUFFER_LIMIT = 500
# Crash window for a resume that never reaches a terminal status. The
# in-memory job still rejects a second resume in this process after it expires.
_RESUME_LEASE_SECONDS = 3600.0
# How long a finished job stays in memory so a client can reconnect to its
# event tail. Running jobs are never removed by this timer.
_FINISHED_JOB_TTL_SECONDS = 600.0
_JOB_SWEEP_SECONDS = 30.0


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
    """A running (or finished) scan and its progress event buffer.

    Event ids are absolute. Dropping a prefix of ``events`` does not renumber
    what remains, so a cursor is the last id the client has, not a list index.
    """

    def __init__(self, scan_id: str, target: str = "") -> None:
        self.scan_id = scan_id
        self.target = target
        self.events: list[dict[str, Any]] = []
        self.status = "running"
        self.detail = ""
        self.task: asyncio.Task[None] | None = None
        self.condition = asyncio.Condition()
        self._next_id = 1
        self.terminal: dict[str, Any] | None = None
        self.finished_at: float | None = None

    def _allocate(self, stage: str, message: str) -> dict[str, Any]:
        event = {"id": self._next_id, "stage": stage, "message": message}
        self._next_id += 1
        return event

    async def publish(self, stage: str, message: str) -> None:
        self.events.append(self._allocate(stage, message))
        overflow = len(self.events) - _EVENT_BUFFER_LIMIT
        if overflow > 0:
            del self.events[:overflow]
        async with self.condition:
            self.condition.notify_all()

    async def finish(self, status: str, detail: str) -> None:
        """Record a terminal status and one SSE event for it."""

        self.status = status
        self.detail = detail
        self.finished_at = time.monotonic()
        self.terminal = self._allocate(status, detail)
        async with self.condition:
            self.condition.notify_all()


def _events_after(events: list[dict[str, Any]], last_id: int) -> list[dict[str, Any]]:
    """Events strictly newer than ``last_id``, in buffer order."""

    return [event for event in events if int(event["id"]) > last_id]


def _format_sse(event: dict[str, Any]) -> str:
    return f"id: {event['id']}\ndata: {json.dumps(event)}\n\n"


def _parse_last_event_id(header: str | None) -> int:
    if header is None or header.strip() == "":
        return 0
    try:
        value = int(header)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="Last-Event-ID must be a non-negative integer"
        ) from exc
    if value < 0:
        raise HTTPException(
            status_code=400, detail="Last-Event-ID must be a non-negative integer"
        )
    return value


def _unauthorized() -> JSONResponse:
    """Same body for a missing token and a wrong token. No hints."""

    return JSONResponse(status_code=401, content={"detail": "Unauthorized"})


def _bearer_token(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = value.strip()
    return token or None


def _presented_token(request: Request) -> str | None:
    """Header on every route; query token only on the SSE events route.

    ``EventSource`` cannot set ``Authorization``. The query value is read here
    and is not written to a log.
    """

    header_token = _bearer_token(request.headers.get("authorization"))
    if header_token is not None:
        return header_token
    path = request.url.path
    if request.method == "GET" and path.startswith("/scans/") and path.endswith("/events"):
        query_token = request.query_params.get("token")
        if query_token:
            return query_token
    return None


def _token_matches(presented: str, expected: str) -> bool:
    try:
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
    except (TypeError, ValueError):
        return False


class _BridgeTokenMiddleware:
    """Reject requests that do not present the local bridge token.

    Raw ASGI, not ``BaseHTTPMiddleware``, so the SSE stream is not buffered.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "")
        path = scope.get("path", "")
        # Preflight does not send Authorization. GET /health is the only
        # unauthenticated data-free probe.
        if method == "OPTIONS" or (method == "GET" and path == "/health"):
            await self.app(scope, receive, send)
            return
        presented = _presented_token(Request(scope))
        if presented is None or not _token_matches(presented, self.token):
            await _unauthorized()(scope, receive, send)
            return
        await self.app(scope, receive, send)


def create_app(
    db_path: str | Path | None = None,
    *,
    config_path: str | Path | None = None,
) -> FastAPI:
    """Build the bridge application. ``db_path`` is injectable for tests."""

    expected_token = load_or_create_bridge_token(bridge_token_path(db_path))
    jobs: dict[str, _ScanJob] = {}

    def _purge_finished_jobs() -> None:
        now = time.monotonic()
        expired = [
            scan_id
            for scan_id, job in jobs.items()
            if job.finished_at is not None
            and job.status != "running"
            and now - job.finished_at >= _FINISHED_JOB_TTL_SECONDS
        ]
        for scan_id in expired:
            jobs.pop(scan_id, None)

    async def _sweep_finished_jobs() -> None:
        while True:
            await asyncio.sleep(_JOB_SWEEP_SECONDS)
            _purge_finished_jobs()

    @contextlib.asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        sweeper = asyncio.create_task(_sweep_finished_jobs())
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper

    app = FastAPI(title="IsaHat Bridge", version=__version__, lifespan=_lifespan)
    # Auth is added first so CORS stays outside it. A 401 then still carries
    # the allow-origin header the webview needs to read the response.
    app.add_middleware(_BridgeTokenMiddleware, token=expected_token)
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
            # ``run`` persists the result and deletes the checkpoint together.
            result = await engine.run()
        except ScopeViolation as exc:
            await job.finish("error", f"scope: {exc}")
        except Exception as exc:  # noqa: BLE001 - surface as job status, not a crash
            await job.finish("error", str(exc))
        else:
            await job.finish("done", result.id)
        finally:
            async with job.condition:
                job.condition.notify_all()
            # A start has no lease; clearing it is a no-op. A resume must not
            # keep the row locked after the job reaches a terminal status.
            store.release_resume_lease(job.scan_id)

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
        job = _ScanJob(scan_id, target=request.target)
        jobs[scan_id] = job
        await job.publish("queued", f"scan queued for {request.target}")
        job.task = asyncio.create_task(_run_scan(job, request))
        return ScanAccepted(scan_id=scan_id, target=request.target)

    @app.get("/scans")
    def list_scans(limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict[str, Any]]:
        _purge_finished_jobs()
        rows = store.list(limit=limit)
        known = {row.id for row in rows}
        out: list[dict[str, Any]] = [
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
        # In-flight scans are not persisted until completion; surface them so
        # closing the UI never "loses" a running audit.
        for scan_id, job in jobs.items():
            if scan_id not in known and job.status == "running":
                out.insert(
                    0,
                    {
                        "id": scan_id,
                        "target": job.target,
                        "profile": "",
                        "started_at": "",
                        "finished_at": None,
                        "findings_total": 0,
                        "by_severity": {},
                        "running": True,
                    },
                )
        return out

    @app.get("/checkpoints")
    def list_checkpoints() -> list[dict[str, Any]]:
        """Interrupted scans that can be resumed, newest first."""

        _purge_finished_jobs()
        return [
            {
                "scan_id": cp.scan_id,
                "target": cp.target,
                "stage": cp.stage,
                "saved_at": cp.saved_at,
                "running": cp.scan_id in jobs and jobs[cp.scan_id].status == "running",
            }
            for cp in store.list_checkpoints()
        ]

    @app.post("/scans/{scan_id}/resume", status_code=202)
    async def resume_scan(scan_id: str) -> ScanAccepted:
        """Resume an interrupted scan from its checkpoint (same engine path as
        `isahat scan <target> --resume <id>`)."""

        _purge_finished_jobs()
        existing = jobs.get(scan_id)
        if existing is not None and existing.status == "running":
            raise HTTPException(status_code=409, detail=f"scan already running: {scan_id}")
        checkpoint = store.load_checkpoint(scan_id)
        if checkpoint is None:
            raise HTTPException(
                status_code=404,
                detail=f"no checkpoint for scan: {scan_id}",
            )
        try:
            contract = require_resume_contract(checkpoint)
        except ResumeRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        acquired = store.try_acquire_resume_lease(scan_id, _RESUME_LEASE_SECONDS)
        if acquired is None:
            raise HTTPException(
                status_code=404,
                detail=f"no checkpoint for scan: {scan_id}",
            )
        if not acquired:
            raise HTTPException(status_code=409, detail=f"scan already running: {scan_id}")
        job = _ScanJob(scan_id, target=checkpoint.target)
        jobs[scan_id] = job
        try:
            await job.publish("resume", f"resuming from stage '{checkpoint.stage}'")
            # Resume re-runs with the same scan id; the engine loads the checkpoint
            # from the store itself. Authorisation was confirmed for the original
            # run — the checkpoint is proof of it. Profile, type and the rate-limit
            # flag come from that checkpoint, not from ScanRequest defaults.
            # Credentials are not in the contract; authenticated scans are rejected
            # above, so auth stays empty.
            request = ScanRequest(
                target=checkpoint.target,
                profile=contract.profile,
                scan_type=contract.scan_type,
                rate_limit_check=contract.rate_limit_check,
                confirmed=True,
            )
            job.task = asyncio.create_task(_run_scan(job, request))
        except Exception:
            jobs.pop(scan_id, None)
            store.release_resume_lease(scan_id)
            raise
        return ScanAccepted(scan_id=scan_id, target=checkpoint.target)

    @app.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> ScanResult:
        result = store.get(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")
        return store.apply_annotations(result)

    @app.get("/scans/{scan_id}/status")
    async def scan_status(scan_id: str) -> ScanStatus:
        _purge_finished_jobs()
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
    async def scan_events(scan_id: str, request: Request) -> StreamingResponse:
        _purge_finished_jobs()
        job = jobs.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")
        last_id = _parse_last_event_id(request.headers.get("last-event-id"))

        async def stream() -> AsyncIterator[str]:
            cursor = last_id
            while True:
                for event in _events_after(list(job.events), cursor):
                    cursor = int(event["id"])
                    yield _format_sse(event)
                terminal = job.terminal
                if job.status != "running":
                    if terminal is not None and int(terminal["id"]) > cursor:
                        yield _format_sse(terminal)
                    return
                async with job.condition:
                    # Re-check under the lock so a publish between the snapshot
                    # and the wait is not lost.
                    if _events_after(job.events, cursor) or job.status != "running":
                        continue
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
