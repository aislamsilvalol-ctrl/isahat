"""Tests for the FastAPI bridge that front-ends (desktop, web) consume."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from isahat.api import create_app
from isahat.core.models import FindingState
from isahat.storage import ScanStore


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "isahat.db")
    token = (tmp_path / "bridge.token").read_text(encoding="utf-8").strip()
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {token}"
        yield test_client


@pytest.fixture()
def stored_scan(client, tmp_path):
    """Run a scan through the bridge against the bundled lab app."""

    import threading  # noqa: PLC0415
    from http.server import ThreadingHTTPServer  # noqa: PLC0415

    from tests.integration.test_engine_e2e import _load_handler  # noqa: PLC0415

    handler = _load_handler()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_address[1]}"
        response = client.post(
            "/scans", json={"target": target, "confirmed": True}
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        deadline = time.time() + 60
        while time.time() < deadline:
            status = client.get(f"/scans/{scan_id}/status").json()
            if status["status"] != "running":
                break
            time.sleep(0.2)
        assert status["status"] == "done", status
        yield scan_id
    finally:
        server.shutdown()
        server.server_close()


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["version"]


def test_scan_requires_explicit_confirmation(client):
    response = client.post("/scans", json={"target": "https://example.com"})
    assert response.status_code == 400
    assert "authorisation" in response.json()["detail"].lower()


def test_full_bridge_flow(client, stored_scan):
    scan_id = stored_scan

    # list shows the finished scan
    scans = client.get("/scans").json()
    assert any(row["id"] == scan_id for row in scans)

    # detail returns findings
    detail = client.get(f"/scans/{scan_id}").json()
    assert detail["id"] == scan_id
    assert len(detail["findings"]) > 0
    finding = detail["findings"][0]

    # annotation: mark the finding as false positive with a comment
    response = client.post(
        f"/scans/{scan_id}/findings/{finding['id']}/annotation",
        json={"state": "false_positive", "comment": "verified: lab fixture"},
    )
    assert response.status_code == 200

    # the state sticks on re-read
    reread = client.get(f"/scans/{scan_id}").json()
    marked = next(f for f in reread["findings"] if f["id"] == finding["id"])
    assert marked["state"] == "false_positive"

    # report endpoint renders in multiple formats
    for fmt, needle in (
        ("json", '"findings"'),
        ("markdown", "# IsaHat Security Audit"),
        ("html", "<!doctype html>"),
        ("csv", "id,title"),
    ):
        report = client.get(f"/scans/{scan_id}/report", params={"fmt": fmt})
        assert report.status_code == 200
        assert needle in report.text


def test_annotation_rejects_unknown_finding(client, stored_scan):
    response = client.post(
        f"/scans/{stored_scan}/findings/ISA-doesnotexist/annotation",
        json={"state": "fixed"},
    )
    assert response.status_code == 404


def test_compare_endpoint(client, tmp_path):
    # Two scans of the same lab target share most findings.
    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        from tests.unit.test_reporting_storage import make_result, sample_finding  # noqa: PLC0415

        store.save(make_result("old1", findings=[sample_finding("A")]))
        store.save(make_result("new1", findings=[sample_finding("B")]))
    body = client.get("/compare", params={"base": "old1", "head": "new1"}).json()
    assert len(body["new"]) == 1
    assert len(body["resolved"]) == 1
    assert "markdown" in body


def test_sse_events_stream_terminates(client, stored_scan):
    """The events endpoint replays the buffer and ends with a terminal event."""

    lines: list[str] = []
    with client.stream("GET", f"/scans/{stored_scan}/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        for line in response.iter_lines():
            if line:
                lines.append(line)
    assert lines  # buffered progress events
    assert any('"done"' in line for line in lines)  # terminal event, then EOF


def test_checkpoints_and_resume_endpoint(client, tmp_path):
    """Interrupted scans appear in /checkpoints and can be resumed via POST."""

    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="dead1234beef",
                target="http://127.0.0.1:9",
                stage="crawl",
                contract=ScanContract(
                    profile="safe", scan_type="web", rate_limit_check=False
                ),
            )
        )

    listed = client.get("/checkpoints").json()
    assert listed[0]["scan_id"] == "dead1234beef"
    assert listed[0]["stage"] == "crawl"
    assert listed[0]["running"] is False

    # Resume against an unreachable target → job starts (202) then errors out,
    # proving the resume path is wired to the engine.
    response = client.post("/scans/dead1234beef/resume")
    assert response.status_code == 202
    assert response.json()["target"] == "http://127.0.0.1:9"

    # A second resume while running conflicts.
    assert client.post("/scans/dead1234beef/resume").status_code in (202, 409)

    # Unknown checkpoint → 404.
    assert client.post("/scans/nope/resume").status_code == 404


def test_resume_without_contract_is_refused(client, tmp_path):
    """A checkpoint saved before contracts existed must not resume as ``safe``."""

    from isahat.core.state import ScanCheckpoint  # noqa: PLC0415

    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(scan_id="legacy1", target="http://127.0.0.1:9", stage="crawl")
        )

    response = client.post("/scans/legacy1/resume")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "no scan contract" in detail
    assert "default" in detail
    assert client.get("/scans/legacy1/status").status_code == 404


def test_resume_authenticated_checkpoint_is_refused(client, tmp_path):
    """Credentials are not stored, so an authenticated scan cannot be resumed."""

    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    secret = "super-secret-token"
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="auth1",
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(
                    profile="safe",
                    scan_type="web",
                    rate_limit_check=False,
                    authenticated=True,
                ),
            )
        )

    response = client.post("/scans/auth1/resume")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "authenticated" in detail.lower()
    assert "credential" in detail.lower()
    assert secret not in detail
    assert client.get("/scans/auth1/status").status_code == 404


def test_resume_restores_saved_contract(client, tmp_path, monkeypatch):
    """Resume rebuilds the original profile, type and rate-limit flag."""

    from isahat.core.engine import ScanEngine  # noqa: PLC0415
    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    captured: dict[str, object] = {}
    original_init = ScanEngine.__init__

    def _init(self, target, config, **kwargs):  # noqa: ANN001
        captured["target"] = target
        captured["profile"] = config.scan.profile
        captured["scan_type"] = kwargs.get("scan_type")
        captured["auth"] = kwargs.get("auth")
        captured["rate_limit_checks"] = config.safety.rate_limit_checks
        original_init(self, target, config, **kwargs)

    async def _run(self):  # noqa: ANN001
        raise RuntimeError("stop-before-scan")

    monkeypatch.setattr(ScanEngine, "__init__", _init)
    monkeypatch.setattr(ScanEngine, "run", _run)
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="contract1",
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(
                    profile="ci", scan_type="api", rate_limit_check=True
                ),
            )
        )

    response = client.post("/scans/contract1/resume")
    assert response.status_code == 202
    deadline = time.time() + 10
    status = {"status": "running"}
    while time.time() < deadline:
        status = client.get("/scans/contract1/status").json()
        if status["status"] != "running":
            break
        time.sleep(0.05)
    assert status["status"] == "error"
    assert captured == {
        "target": "http://127.0.0.1:9",
        "profile": "ci",
        "scan_type": "api",
        "auth": None,
        "rate_limit_checks": True,
    }


def test_resume_lease_is_exclusive(tmp_path):
    """BEGIN IMMEDIATE lets only one of several concurrent claims succeed."""

    import threading  # noqa: PLC0415

    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    db = tmp_path / "lease.db"
    scan_id = "lease1"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id=scan_id,
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )

    results: list[bool | None] = []
    barrier = threading.Barrier(8)

    def claim() -> None:
        barrier.wait()
        with ScanStore(db) as store:
            results.append(store.try_acquire_resume_lease(scan_id, 30))

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert results.count(False) == 7

    with ScanStore(db) as store:
        store.release_resume_lease(scan_id)
        assert store.try_acquire_resume_lease(scan_id, 30) is True
        store._conn.execute(
            "UPDATE checkpoints SET lease_until = ? WHERE scan_id = ?",
            ("2000-01-01T00:00:00+00:00", scan_id),
        )
        store._conn.commit()
        assert store.try_acquire_resume_lease(scan_id, 30) is True
        assert store.try_acquire_resume_lease("missing", 30) is None


def test_resume_while_lease_held_returns_409(client, tmp_path):
    """A second resume is 409 even when this process has no in-memory job."""

    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="held1",
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )
        assert store.try_acquire_resume_lease("held1", 60) is True

    response = client.post("/scans/held1/resume")
    assert response.status_code == 409
    assert "already running" in response.json()["detail"]
    assert client.get("/scans/held1/status").status_code == 404


def test_resume_lease_released_when_job_finishes(client, tmp_path, monkeypatch):
    from isahat.core.engine import ScanEngine  # noqa: PLC0415
    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    async def _run(self):  # noqa: ANN001
        raise RuntimeError("stop-before-scan")

    monkeypatch.setattr(ScanEngine, "run", _run)
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="again1",
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )

    assert client.post("/scans/again1/resume").status_code == 202
    deadline = time.time() + 10
    status = {"status": "running"}
    while time.time() < deadline:
        status = client.get("/scans/again1/status").json()
        if status["status"] != "running":
            break
        time.sleep(0.05)
    assert status["status"] == "error"
    assert client.post("/scans/again1/resume").status_code == 202


def test_lease_column_migrates_existing_database(tmp_path):
    import sqlite3  # noqa: PLC0415

    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """
        CREATE TABLE checkpoints (
            scan_id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            stage TEXT NOT NULL,
            payload TEXT NOT NULL,
            saved_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO checkpoints VALUES ('old', 'http://127.0.0.1:9', 'crawl', '{}', 't')"
    )
    conn.commit()
    conn.close()

    with ScanStore(db) as store:
        columns = [row[1] for row in store._conn.execute("PRAGMA table_info(checkpoints)")]
        assert "lease_until" in columns
        assert store.try_acquire_resume_lease("old", 30) is True


def test_unknown_scan_404(client):
    assert client.get("/scans/nope").status_code == 404
    assert client.get("/scans/nope/status").status_code == 404
    assert client.get("/scans/nope/events").status_code == 404


def test_annotation_state_enum_validated(client, stored_scan):
    scan = client.get(f"/scans/{stored_scan}").json()
    finding_id = scan["findings"][0]["id"]
    response = client.post(
        f"/scans/{stored_scan}/findings/{finding_id}/annotation",
        json={"state": "not-a-state"},
    )
    assert response.status_code == 422


def _sse_events(client, scan_id: str, last_event_id: int | None = None) -> list[dict[str, object]]:
    import json  # noqa: PLC0415

    headers = {} if last_event_id is None else {"Last-Event-ID": str(last_event_id)}
    parsed: list[dict[str, object]] = []
    current_id: int | None = None
    with client.stream("GET", f"/scans/{scan_id}/events", headers=headers) as response:
        assert response.status_code == 200
        for line in response.iter_lines():
            if not line:
                continue
            if line.startswith("id: "):
                current_id = int(line.removeprefix("id: "))
            elif line.startswith("data: "):
                payload = json.loads(line.removeprefix("data: "))
                assert payload["id"] == current_id
                parsed.append(payload)
                current_id = None
    return parsed


def test_event_ids_survive_buffer_trim(monkeypatch):
    """Trimming the buffer must not renumber events or skip ones still stored."""

    from isahat.api.app import _events_after, _ScanJob  # noqa: PLC0415

    monkeypatch.setattr("isahat.api.app._EVENT_BUFFER_LIMIT", 3)
    job = _ScanJob("buffer")

    async def publish_all() -> None:
        for index in range(5):
            await job.publish("stage", f"m{index}")

    import asyncio  # noqa: PLC0415

    asyncio.run(publish_all())
    assert [event["id"] for event in job.events] == [3, 4, 5]
    # A client that already saw ids 1 and 2 still receives 3, 4 and 5.
    assert [event["id"] for event in _events_after(job.events, 2)] == [3, 4, 5]
    assert [event["message"] for event in _events_after(job.events, 4)] == ["m4"]
    assert _events_after(job.events, 5) == []


def test_sse_reconnect_does_not_skip_or_repeat(client, tmp_path, monkeypatch):
    from isahat.core.engine import ScanEngine  # noqa: PLC0415
    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    async def _run(self):  # noqa: ANN001
        raise RuntimeError("stop-before-scan")

    monkeypatch.setattr(ScanEngine, "run", _run)
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="sse1",
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )

    assert client.post("/scans/sse1/resume").status_code == 202
    deadline = time.time() + 10
    status = {"status": "running"}
    while time.time() < deadline:
        status = client.get("/scans/sse1/status").json()
        if status["status"] != "running":
            break
        time.sleep(0.05)
    assert status["status"] == "error"

    first = _sse_events(client, "sse1")
    ids = [int(event["id"]) for event in first]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    assert len(ids) >= 2
    midpoint = ids[0]
    second = _sse_events(client, "sse1", last_event_id=midpoint)
    assert [int(event["id"]) for event in second] == [event_id for event_id in ids if event_id > midpoint]
    assert second == [event for event in first if int(event["id"]) > midpoint]
    assert _sse_events(client, "sse1", last_event_id=ids[-1]) == []


def test_sse_rejects_malformed_last_event_id(client, tmp_path, monkeypatch):
    from isahat.core.engine import ScanEngine  # noqa: PLC0415
    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    async def _run(self):  # noqa: ANN001
        raise RuntimeError("stop-before-scan")

    monkeypatch.setattr(ScanEngine, "run", _run)
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="ssebad",
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )
    assert client.post("/scans/ssebad/resume").status_code == 202
    response = client.get("/scans/ssebad/events", headers={"Last-Event-ID": "nope"})
    assert response.status_code == 400


def test_finished_job_is_removed_after_ttl(client, tmp_path, monkeypatch):
    from isahat.core.engine import ScanEngine  # noqa: PLC0415
    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415

    async def _run(self):  # noqa: ANN001
        raise RuntimeError("stop-before-scan")

    monkeypatch.setattr(ScanEngine, "run", _run)
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="ttl1",
                target="http://127.0.0.1:9",
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )

    assert client.post("/scans/ttl1/resume").status_code == 202
    deadline = time.time() + 10
    while time.time() < deadline:
        body = client.get("/scans/ttl1/status").json()
        if body["status"] != "running":
            break
        time.sleep(0.05)
    else:
        raise AssertionError("job did not finish")
    assert client.get("/scans/ttl1/events").status_code == 200

    monkeypatch.setattr("isahat.api.app._FINISHED_JOB_TTL_SECONDS", 0.0)
    assert client.get("/scans/ttl1/events").status_code == 404
    # The checkpoint was not finalized, so status no longer has a live job.
    assert client.get("/scans/ttl1/status").status_code == 404


def test_finding_state_values_cover_review_workflow():
    assert {s.value for s in FindingState} >= {"open", "false_positive", "fixed"}
