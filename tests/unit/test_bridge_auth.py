"""Local bearer token on the bridge. The token value is not logged or printed."""

from __future__ import annotations

import stat

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from isahat.api.app import create_app
from isahat.api.token import (
    BridgeTokenError,
    bridge_token_path,
    load_or_create_bridge_token,
    non_loopback_warning,
)
from isahat.cli.main import app as cli_app


def _token(tmp_path) -> str:
    return (tmp_path / "bridge.token").read_text(encoding="utf-8").strip()


def test_health_does_not_require_a_token(tmp_path):
    app = create_app(tmp_path / "isahat.db")
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert _token(tmp_path) not in response.text


def test_missing_and_wrong_token_are_the_same_401(tmp_path):
    app = create_app(tmp_path / "isahat.db")
    secret = _token(tmp_path)
    with TestClient(app) as client:
        missing = client.get("/scans")
        wrong = client.get("/scans", headers={"Authorization": "Bearer not-the-token"})
        opened = client.get("/openapi.json")
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert opened.status_code == 401
    assert missing.json() == wrong.json() == {"detail": "Unauthorized"}
    assert secret not in missing.text
    assert secret not in wrong.text


def test_correct_bearer_token_allows_the_route(tmp_path):
    app = create_app(tmp_path / "isahat.db")
    secret = _token(tmp_path)
    with TestClient(app) as client:
        response = client.get("/scans", headers={"Authorization": f"Bearer {secret}"})
    assert response.status_code == 200
    assert response.json() == []


def test_token_file_is_mode_0600_and_reused(tmp_path):
    db = tmp_path / "isahat.db"
    path = bridge_token_path(db)
    first = load_or_create_bridge_token(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    second = load_or_create_bridge_token(path)
    assert second == first
    again = create_app(db)
    with TestClient(again) as client:
        response = client.get("/scans", headers={"Authorization": f"Bearer {first}"})
    assert response.status_code == 200
    assert path.read_text(encoding="utf-8").strip() == first


def test_loose_token_file_is_refused_without_echoing_the_secret(tmp_path):
    path = bridge_token_path(tmp_path / "isahat.db")
    secret = load_or_create_bridge_token(path)
    path.chmod(0o644)
    with pytest.raises(BridgeTokenError) as raised:
        load_or_create_bridge_token(path)
    message = str(raised.value)
    assert "0600" in message
    assert secret not in message
    with pytest.raises(BridgeTokenError):
        create_app(tmp_path / "isahat.db")


def test_events_query_token_is_accepted_only_on_that_route(tmp_path):
    app = create_app(tmp_path / "isahat.db")
    secret = _token(tmp_path)
    with TestClient(app) as client:
        blocked = client.get("/scans", params={"token": secret})
        assert blocked.status_code == 401
        started = client.post(
            "/scans",
            headers={"Authorization": f"Bearer {secret}"},
            json={"target": "http://127.0.0.1:9", "confirmed": True},
        )
        assert started.status_code == 202
        scan_id = started.json()["scan_id"]
        denied = client.get(f"/scans/{scan_id}/events")
        assert denied.status_code == 401
        with client.stream("GET", f"/scans/{scan_id}/events", params={"token": secret}) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            assert any(line for line in response.iter_lines())


def test_bridge_token_command_prints_the_path_only(tmp_path):
    db = tmp_path / "isahat.db"
    secret = load_or_create_bridge_token(bridge_token_path(db))
    location = str(bridge_token_path(db))
    hidden = CliRunner().invoke(cli_app, ["bridge", "token", "--db", str(db)])
    assert hidden.exit_code == 0
    assert location not in hidden.stdout
    assert secret not in hidden.stdout
    result = CliRunner().invoke(cli_app, ["bridge", "token", "--path", "--db", str(db)])
    assert result.exit_code == 0
    assert location in result.stdout
    assert secret not in result.stdout


def test_non_loopback_warning_names_no_secret():
    assert non_loopback_warning("127.0.0.1") is None
    assert non_loopback_warning("localhost") is None
    warning = non_loopback_warning("0.0.0.0")
    assert warning is not None
    assert "token file" in warning
    assert "Bearer" not in warning
