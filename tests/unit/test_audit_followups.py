"""Focused checks for the P2/P3 audit follow-ups.

Profile and scan type are labels. A new scan may only use the ones the engine
actually runs. An in-flight bridge job reports the time it started.
"""

from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from isahat.api import create_app
from isahat.core.config import unimplemented_scan_mode_reason


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "isahat.db")
    token = (tmp_path / "bridge.token").read_text(encoding="utf-8").strip()
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {token}"
        yield test_client


def test_implemented_scan_mode_is_only_safe_web():
    assert unimplemented_scan_mode_reason("safe", "web") is None
    assert "not available yet" in (unimplemented_scan_mode_reason("standard", "web") or "")
    assert "not available yet" in (unimplemented_scan_mode_reason("safe", "api") or "")


def test_cli_rejects_unimplemented_profile_and_type():
    from typer.testing import CliRunner  # noqa: PLC0415

    from isahat.cli.main import app as cli_app  # noqa: PLC0415

    runner = CliRunner()
    profile = runner.invoke(
        cli_app,
        ["scan", "https://example.com", "--yes", "--no-store", "--profile", "standard"],
    )
    assert profile.exit_code == 2
    assert "not available yet" in profile.output
    assert "standard" in profile.output

    kind = runner.invoke(
        cli_app,
        ["scan", "https://example.com", "--yes", "--no-store", "--type", "api"],
    )
    assert kind.exit_code == 2
    assert "not available yet" in kind.output
    assert "api" in kind.output

    # The implemented labels still reach the authorisation check.
    allowed = runner.invoke(
        cli_app,
        ["scan", "https://example.com", "--no-store", "--profile", "safe", "--type", "web"],
    )
    assert allowed.exit_code == 2
    assert "not available yet" not in allowed.output
    assert "no TTY" in allowed.output


def test_cli_resume_keeps_saved_mode(tmp_path, monkeypatch):
    """A checkpoint may carry an old label. Resume must not reject it."""

    from typer.testing import CliRunner  # noqa: PLC0415

    from isahat.cli.main import app as cli_app  # noqa: PLC0415
    from isahat.core.engine import ScanEngine  # noqa: PLC0415
    from isahat.core.state import ScanCheckpoint, ScanContract  # noqa: PLC0415
    from isahat.storage import ScanStore  # noqa: PLC0415

    target = "https://example.com"
    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="c1",
                target=target,
                stage="detectors",
                contract=ScanContract(profile="deep", scan_type="api", rate_limit_check=True),
            )
        )

    captured: dict[str, object] = {}

    def _scan(self):  # noqa: ANN001
        captured["profile"] = self.config.scan.profile
        captured["scan_type"] = self.scan_type
        raise RuntimeError("stop-before-network")

    monkeypatch.setattr(ScanEngine, "scan", _scan)
    result = CliRunner().invoke(
        cli_app,
        [
            "scan",
            target,
            "--resume",
            "c1",
            "--db",
            str(db),
            "--yes",
            "--quiet",
            "--profile",
            "standard",
            "--type",
            "api",
        ],
    )
    assert result.exit_code == 1
    assert captured == {"profile": "deep", "scan_type": "api"}


def test_api_rejects_unimplemented_profile_and_type(client):
    profile = client.post(
        "/scans",
        json={"target": "https://example.com", "confirmed": True, "profile": "standard"},
    )
    assert profile.status_code == 400
    assert "not available yet" in profile.json()["detail"]

    kind = client.post(
        "/scans",
        json={"target": "https://example.com", "confirmed": True, "scan_type": "api"},
    )
    assert kind.status_code == 400
    assert "not available yet" in kind.json()["detail"]
    assert client.get("/scans").json() == []


def test_running_scan_lists_a_start_time(client, monkeypatch):
    from isahat.core.engine import ScanEngine  # noqa: PLC0415

    release = threading.Event()

    async def _run(self):  # noqa: ANN001
        await asyncio.to_thread(release.wait)
        raise RuntimeError("stopped")

    monkeypatch.setattr(ScanEngine, "run", _run)
    try:
        response = client.post(
            "/scans",
            json={"target": "http://127.0.0.1:9", "confirmed": True},
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        deadline = time.time() + 5
        row = None
        while time.time() < deadline:
            rows = client.get("/scans").json()
            row = next((item for item in rows if item["id"] == scan_id), None)
            if row is not None and row["running"] and row["started_at"]:
                break
            time.sleep(0.05)
        assert row is not None
        assert row["running"] is True
        parsed = datetime.fromisoformat(row["started_at"])
        assert parsed.tzinfo is not None
        status = client.get(f"/scans/{scan_id}/status").json()
        assert status["status"] == "running"
        assert status["started_at"] == row["started_at"]
    finally:
        release.set()
