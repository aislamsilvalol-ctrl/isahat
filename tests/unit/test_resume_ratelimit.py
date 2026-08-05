"""Tests for the opt-in rate-limiting detector and scan resume checkpoints."""

from __future__ import annotations

from isahat.core.detectors.base import DetectorContext
from isahat.core.detectors.rate_limiting import RateLimitingDetector
from isahat.core.models import Confidence, Severity
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
