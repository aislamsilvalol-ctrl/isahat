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
from isahat.core.auth import AuthConfig
from isahat.core.config import ScanConfig
from isahat.core.crawler import Crawler
from isahat.core.detectors import default_detectors
from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.http import HttpResponse, SafeHttpClient
from isahat.core.injection import collect_get_points
from isahat.core.models import Finding, ScanResult, Technology
from isahat.core.risk import sort_by_priority
from isahat.core.scope import Scope

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
    ) -> None:
        self.target = target
        self.config = config
        self.scan_type = scan_type
        self._detectors = list(detectors) if detectors is not None else default_detectors()
        self._on_progress = on_progress
        self._auth = auth
        self.scope = Scope.from_config(target, config)

    def _emit(self, stage: str, message: str) -> None:
        if self._on_progress is not None:
            self._on_progress(stage, message)

    async def run(self) -> ScanResult:
        started = datetime.now(UTC)
        result = ScanResult(
            id=uuid.uuid4().hex[:12],
            target=self.target,
            profile=self.config.scan.profile,
            scan_type=self.scan_type,
            authenticated=bool(self._auth and not self._auth.is_empty()),
            started_at=started,
            scope=self.scope.to_info(),
            isahat_version=__version__,
        )

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
            self._emit(
                "crawl",
                f"discovered {len(crawl.endpoints)} endpoints, {len(crawl.forms)} forms",
            )

            result.technologies = self._collect_technologies(crawl.responses)
            if result.technologies:
                names = ", ".join(t.name for t in result.technologies)
                self._emit("fingerprint", f"technologies: {names}")

            points = collect_get_points([e.url for e in crawl.endpoints], crawl.forms)
            if points:
                self._emit("discover", f"{len(points)} injection points")

            ctx = DetectorContext(
                target=self.target,
                scope=self.scope,
                client=client,
                responses=crawl.responses,
                forms=crawl.forms,
                injection_points=points,
                destructive=self.config.safety.destructive_tests,
            )
            result.findings = await self._run_detectors(ctx)
            result.stats.requests_made = client.requests_made

        result.findings = sort_by_priority(result.findings)
        result.finished_at = datetime.now(UTC)
        result.recompute_stats()
        self._emit("done", f"{len(result.findings)} findings")
        return result

    def _collect_technologies(self, responses: list[HttpResponse]) -> list[Technology]:
        merged: dict[str, Technology] = {}
        for response in responses:
            for item in tech.detect(response):
                key = item.name.lower()
                current = merged.get(key)
                if current is None or (item.version and not current.version):
                    merged[key] = item
        return list(merged.values())

    async def _run_detectors(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self._detectors:
            self._emit("analyze", f"running {detector.name}")
            try:
                findings.extend(await detector.run(ctx))
            except Exception as exc:  # noqa: BLE001 - one detector must not fail the scan
                self._emit("error", f"detector {detector.name} failed: {exc}")
        return findings

    def scan(self) -> ScanResult:
        """Blocking wrapper around :meth:`run` for synchronous callers."""

        return asyncio.run(self.run())
