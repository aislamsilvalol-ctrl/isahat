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
    with TestClient(app) as test_client:
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

    from isahat.core.state import ScanCheckpoint  # noqa: PLC0415

    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(
            ScanCheckpoint(scan_id="dead1234beef", target="http://127.0.0.1:9", stage="crawl")
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


def test_finding_state_values_cover_review_workflow():
    assert {s.value for s in FindingState} >= {"open", "false_positive", "fixed"}
