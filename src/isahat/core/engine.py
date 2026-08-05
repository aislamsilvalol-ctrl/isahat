"""The scan engine — orchestrates the full audit pipeline.

Pipeline: build scope -> crawl within scope -> fingerprint technologies ->
run detectors -> assemble a :class:`~isahat.core.models.ScanResult`.

The engine exposes both an async API (:meth:`run`) and a blocking convenience
wrapper (:meth:`scan`) so the CLI and future front-ends share identical logic.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from isahat import __version__
from isahat.core import tech
from isahat.core.api import discover_apis
from isahat.core.auth import AuthConfig
from isahat.core.config import ScanConfig
from isahat.core.crawler import Crawler
from isahat.core.detectors import default_detectors
from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.detectors.rate_limiting import RateLimitingDetector
from isahat.core.http import HttpResponse, SafeHttpClient
from isahat.core.injection import collect_get_points
from isahat.core.models import ScanResult, Technology
from isahat.core.risk import sort_by_priority
from isahat.core.scope import Scope
from isahat.core.state import (
    STAGE_CRAWL,
    CheckpointStore,
    ResponseSnapshot,
    ScanCheckpoint,
)

ProgressCallback = Callable[[str, str], None]


class ScanEngine:
    """Runs an audit for a single target using a resolved configuration."""

    def __init__(
        self,
        target: str,
        config: ScanConfig,
        *,
        scan_type: str = "web",
        detectors: Iterable[Detector] | None = None,
        on_progress: ProgressCallback | None = None,
        auth: AuthConfig | None = None,
        checkpoint_store: CheckpointStore | None = None,
        scan_id: str | None = None,
    ) -> None:
        self.target = target
        self.config = config
        self.scan_type = scan_type
        self._detectors = list(detectors) if detectors is not None else default_detectors()
        if config.safety.rate_limit_checks:
            self._detectors.append(RateLimitingDetector())
        self._on_progress = on_progress
        self._auth = auth
        self.scope = Scope.from_config(target, config)
        self._checkpoints = checkpoint_store
        self.scan_id = scan_id or uuid.uuid4().hex[:12]

    def _emit(self, stage: str, message: str) -> None:
        if self._on_progress is not None:
            self._on_progress(stage, message)

    def _load_checkpoint(self) -> ScanCheckpoint | None:
        if self._checkpoints is None:
            return None
        checkpoint = self._checkpoints.load_checkpoint(self.scan_id)
        if checkpoint is not None and checkpoint.target != self.target:
            self._emit("resume", "checkpoint target mismatch; starting fresh")
            return None
        return checkpoint

    def _save_checkpoint(self, checkpoint: ScanCheckpoint) -> None:
        if self._checkpoints is not None:
            self._checkpoints.save_checkpoint(checkpoint)

    async def run(self) -> ScanResult:
        started = datetime.now(UTC)
        result = ScanResult(
            id=self.scan_id,
            target=self.target,
            profile=self.config.scan.profile,
            scan_type=self.scan_type,
            authenticated=bool(self._auth and not self._auth.is_empty()),
            started_at=started,
            scope=self.scope.to_info(),
            isahat_version=__version__,
        )

        checkpoint = self._load_checkpoint()
        if checkpoint is not None:
            self._emit("resume", f"resuming scan {self.scan_id} from stage '{checkpoint.stage}'")
            result.findings = list(checkpoint.findings)

        async with SafeHttpClient(
            self.scope,
            timeout=self.config.scan.timeout,
            rate_limit=self.config.safety.rate_limit,
            follow_redirects=self.config.scan.follow_redirects,
            destructive=self.config.safety.destructive_tests,
            concurrency=self.config.scan.concurrency,
            auth_headers=self._auth.headers if self._auth else None,
            cookies=self._auth.cookies if self._auth else None,
        ) as client:
            # Stage 1: crawl (skip when a checkpoint already holds the surface).
            if checkpoint is not None and checkpoint.stage != STAGE_CRAWL:
                crawl_responses = [s.to_response() for s in checkpoint.responses]
                result.endpoints = list(checkpoint.endpoints)
                result.forms = list(checkpoint.forms)
                self._emit(
                    "crawl",
                    f"reused {len(result.endpoints)} endpoints, "
                    f"{len(result.forms)} forms from checkpoint",
                )
            else:
                self._emit("crawl", f"crawling {self.target}")
                crawler = Crawler(
                    client,
                    self.scope,
                    max_pages=self.config.scan.max_pages,
                    max_depth=self.config.scan.max_depth,
                )
                crawl = await crawler.crawl(self.target)
                result.endpoints = crawl.endpoints
                result.forms = crawl.forms
                crawl_responses = crawl.responses
                self._emit(
                    "crawl",
                    f"discovered {len(crawl.endpoints)} endpoints, {len(crawl.forms)} forms",
                )
                checkpoint = self._new_checkpoint(result, crawl_responses, stage="apis")
                self._save_checkpoint(checkpoint)

            result.technologies = self._collect_technologies(crawl_responses)
            if result.technologies:
                names = ", ".join(t.name for t in result.technologies)
                self._emit("fingerprint", f"technologies: {names}")

            # Stage 2: API discovery.
            if checkpoint is not None and checkpoint.stage not in (STAGE_CRAWL, "apis"):
                result.apis = list(checkpoint.apis)
                self._emit("discover", f"reused {len(result.apis)} API surfaces from checkpoint")
            else:
                self._emit("discover", "probing API surfaces (OpenAPI/GraphQL)")
                result.apis = await discover_apis(client, self.target)
                if result.apis:
                    kinds = ", ".join(f"{a.kind}@{a.url}" for a in result.apis)
                    self._emit("discover", f"api surfaces: {kinds}")
                assert checkpoint is not None  # saved after crawl
                checkpoint.stage = "detectors"
                checkpoint.apis = result.apis
                self._save_checkpoint(checkpoint)

            points = collect_get_points([e.url for e in result.endpoints], result.forms)
            if points:
                self._emit("discover", f"{len(points)} injection points")

            ctx = DetectorContext(
                target=self.target,
                scope=self.scope,
                client=client,
                responses=crawl_responses,
                forms=result.forms,
                injection_points=points,
                apis=result.apis,
                destructive=self.config.safety.destructive_tests,
                rate_limit_burst=self.config.safety.rate_limit_burst,
                rate_limit_interval=self.config.safety.rate_limit_interval,
            )
            await self._run_detectors(ctx, result, checkpoint)
            result.stats.requests_made = client.requests_made

        result.findings = sort_by_priority(result.findings)
        result.finished_at = datetime.now(UTC)
        result.recompute_stats()
        if self._checkpoints is not None:
            self._checkpoints.delete_checkpoint(self.scan_id)
        self._emit("done", f"{len(result.findings)} findings")
        return result

    def _new_checkpoint(
        self, result: ScanResult, responses: list[HttpResponse], *, stage: str
    ) -> ScanCheckpoint:
        return ScanCheckpoint(
            scan_id=self.scan_id,
            target=self.target,
            stage=stage,
            endpoints=result.endpoints,
            forms=result.forms,
            responses=[ResponseSnapshot.from_response(r) for r in responses],
        )

    def _collect_technologies(self, responses: list[HttpResponse]) -> list[Technology]:
        merged: dict[str, Technology] = {}
        for response in responses:
            for item in tech.detect(response):
                key = item.name.lower()
                current = merged.get(key)
                if current is None or (item.version and not current.version):
                    merged[key] = item
        return list(merged.values())

    async def _run_detectors(
        self,
        ctx: DetectorContext,
        result: ScanResult,
        checkpoint: ScanCheckpoint | None,
    ) -> None:
        completed = set(checkpoint.completed_detectors) if checkpoint else set()
        for detector in self._detectors:
            if detector.name in completed:
                self._emit("analyze", f"skipping {detector.name} (already done)")
                continue
            self._emit("analyze", f"running {detector.name}")
            try:
                result.findings.extend(await detector.run(ctx))
            except Exception as exc:  # noqa: BLE001 - one detector must not fail the scan
                self._emit("error", f"detector {detector.name} failed: {exc}")
            if checkpoint is not None:
                checkpoint.completed_detectors.append(detector.name)
                checkpoint.findings = list(result.findings)
                self._save_checkpoint(checkpoint)

    def scan(self) -> ScanResult:
        """Blocking wrapper around :meth:`run` for synchronous callers."""

        return asyncio.run(self.run())
