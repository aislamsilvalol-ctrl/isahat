"""Tests for the opt-in rate-limiting detector and scan resume checkpoints."""

from __future__ import annotations

import sqlite3

import pytest

from isahat.core.config import ScanConfig
from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.detectors.rate_limiting import RateLimitingDetector
from isahat.core.engine import ScanEngine
from isahat.core.models import Confidence, ScanResult, Severity
from isahat.core.state import ResponseSnapshot, ScanCheckpoint
from isahat.storage import ScanStore
from tests.unit.helpers import FakeClient, make_response, make_scope

TARGET = "https://example.com"


def _ctx(client, *, responses, burst=10, interval=0.0):
    scope = make_scope(TARGET)
    return DetectorContext(
        target=TARGET,
        scope=scope,
        client=client,
        responses=responses,
        rate_limit_burst=burst,
        rate_limit_interval=interval,
    )


# --- Rate limiting --------------------------------------------------------


async def test_rate_limiting_missing_is_flagged_with_full_log():
    scope = make_scope(TARGET)
    client = FakeClient(
        scope, {"/login": make_response(TARGET + "/login", text="<form></form>")}
    )
    ctx = _ctx(client, responses=[make_response(TARGET + "/login")], burst=10)
    findings = await RateLimitingDetector().run(ctx)
    assert client.requests_made == 10  # full burst completed
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.PROBABLE
    assert finding.cwe == "CWE-307"
    # Every request/response of the burst is logged in evidence.
    assert "attempt 10" in (finding.evidence.response or "")


async def test_rate_limiting_stops_burst_on_first_429():
    hits = {"count": 0}

    def login(url, headers):
        hits["count"] += 1
        if hits["count"] >= 4:
            return make_response(url, status=429, text="slow down")
        return make_response(url, text="<form></form>")

    scope = make_scope(TARGET)
    client = FakeClient(scope, {"/login": login})
    ctx = _ctx(client, responses=[make_response(TARGET + "/login")], burst=10)
    assert await RateLimitingDetector().run(ctx) == []
    assert hits["count"] == 4  # interrupted immediately on 429


async def test_rate_limiting_ignores_non_auth_endpoints():
    scope = make_scope(TARGET)
    client = FakeClient(scope, {"/about": make_response(TARGET + "/about")})
    ctx = _ctx(client, responses=[make_response(TARGET + "/about")], burst=10)
    assert await RateLimitingDetector().run(ctx) == []
    assert client.requests_made == 0  # never probed a non-auth endpoint


async def test_rate_limiting_burst_is_hard_capped():
    scope = make_scope(TARGET)
    client = FakeClient(
        scope, {"/login": make_response(TARGET + "/login", text="<form></form>")}
    )
    ctx = _ctx(client, responses=[make_response(TARGET + "/login")], burst=500)
    findings = await RateLimitingDetector().run(ctx)
    assert client.requests_made <= 30  # hard cap, regardless of configuration
    assert len(findings) == 1


# --- Checkpoints ----------------------------------------------------------


def test_checkpoint_store_roundtrip(tmp_path):
    with ScanStore(tmp_path / "isahat.db") as store:
        checkpoint = ScanCheckpoint(
            scan_id="abc123",
            target=TARGET,
            stage="detectors",
            requests_made=12,
            responses=[
                ResponseSnapshot.from_response(make_response(TARGET + "/login", status=200))
            ],
        )
        store.save_checkpoint(checkpoint)
        loaded = store.load_checkpoint("abc123")
        assert loaded is not None
        assert loaded.stage == "detectors"
        assert loaded.requests_made == 12
        restored = loaded.responses[0].to_response()
        assert restored.url == TARGET + "/login"
        assert restored.status == 200
        store.delete_checkpoint("abc123")
        assert store.load_checkpoint("abc123") is None


def test_checkpoint_upsert_overwrites(tmp_path):
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(ScanCheckpoint(scan_id="x1", target=TARGET, stage="apis"))
        store.save_checkpoint(ScanCheckpoint(scan_id="x1", target=TARGET, stage="detectors"))
        loaded = store.load_checkpoint("x1")
        assert loaded is not None and loaded.stage == "detectors"


def _finished_result(scan_id: str) -> ScanResult:
    result = ScanResult(
        id=scan_id,
        target=TARGET,
        scope={"target": TARGET, "allowed_hosts": ["example.com"]},
    )
    result.finished_at = result.started_at
    result.recompute_stats()
    return result


def test_finalize_scan_saves_result_and_drops_checkpoint(tmp_path):
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(ScanCheckpoint(scan_id="abc123", target=TARGET, stage="detectors"))
        store.finalize_scan(_finished_result("abc123"))
        assert store.get("abc123") is not None
        assert store.load_checkpoint("abc123") is None


def test_finalize_scan_rolls_back_when_commit_fails(tmp_path):
    """A failure before commit must not delete the checkpoint or publish the scan."""

    class _CommitProxy:
        def __init__(self, real: sqlite3.Connection) -> None:
            self._real = real
            self.statements: list[str] = []

        def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
            self.statements.append(sql)
            return self._real.execute(sql, parameters)

        def commit(self) -> None:
            blob = " ".join(self.statements).lower()
            if "insert into scans" in blob and "delete from checkpoints" in blob:
                raise sqlite3.OperationalError("injected commit failure")
            self._real.commit()

        def rollback(self) -> None:
            self._real.rollback()

        def __getattr__(self, name: str) -> object:
            return getattr(self._real, name)

    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(ScanCheckpoint(scan_id="abc123", target=TARGET, stage="detectors"))
        store._conn = _CommitProxy(store._conn)  # type: ignore[assignment]
        with pytest.raises(sqlite3.OperationalError, match="injected commit failure"):
            store.finalize_scan(_finished_result("abc123"))
        assert store.get("abc123") is None
        checkpoint = store.load_checkpoint("abc123")
        assert checkpoint is not None
        assert checkpoint.stage == "detectors"


def test_raising_detector_is_not_completed_and_resume_reruns_it(tmp_path):
    calls = {"ok": 0, "boom": 0, "tail": 0}
    stop = {"on": True}

    class OkDetector(Detector):
        name = "ok-one"
        category = "test"

        async def run(self, ctx: DetectorContext) -> list:
            calls["ok"] += 1
            return []

    class BoomDetector(Detector):
        name = "boom"
        category = "test"

        async def run(self, ctx: DetectorContext) -> list:
            calls["boom"] += 1
            raise RuntimeError("detector failed")

    class TailDetector(Detector):
        name = "tail"
        category = "test"

        async def run(self, ctx: DetectorContext) -> list:
            calls["tail"] += 1
            if stop["on"]:
                raise KeyboardInterrupt
            return []

    scan_id = "resume-boom"
    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id=scan_id,
                target=TARGET,
                stage="detectors",
                responses=[ResponseSnapshot.from_response(make_response(TARGET + "/"))],
            )
        )
        first = ScanEngine(
            TARGET,
            ScanConfig(),
            detectors=[OkDetector(), BoomDetector(), TailDetector()],
            checkpoint_store=store,
            scan_id=scan_id,
        )
        with pytest.raises(KeyboardInterrupt):
            first.scan()
        assert store.get(scan_id) is None
        checkpoint = store.load_checkpoint(scan_id)
        assert checkpoint is not None
        assert checkpoint.completed_detectors == ["ok-one"]
        assert calls == {"ok": 1, "boom": 1, "tail": 1}

        stop["on"] = False
        second = ScanEngine(
            TARGET,
            ScanConfig(),
            detectors=[OkDetector(), BoomDetector(), TailDetector()],
            checkpoint_store=store,
            scan_id=scan_id,
        )
        result = second.scan()
        assert calls == {"ok": 1, "boom": 2, "tail": 2}
        assert result.id == scan_id
        assert store.get(scan_id) is not None
        assert store.load_checkpoint(scan_id) is None
