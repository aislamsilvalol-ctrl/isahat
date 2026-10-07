"""Redirects must be re-checked against scope before the next hop is sent."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from isahat.core.config import ScanConfig
from isahat.core.http import SafeHttpClient
from isahat.core.scope import Scope

_TOKEN = "test-token-value"


class _Handler(BaseHTTPRequestHandler):
    records: list[dict[str, str]] = []
    # Set by the cross-origin test so /cross points at a second local port.
    cross_location: str = ""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        port = self.server.server_address[1]
        path = urlparse(self.path).path
        self.records.append(
            {
                "path": path,
                "authorization": self.headers.get("Authorization", ""),
                "cookie": self.headers.get("Cookie", ""),
            }
        )
        status = 200
        body = b"ok"
        location: str | None = None
        if path == "/out":
            status, body = 302, b"redirect"
            location = f"http://localhost:{port}/secret"
        elif path == "/hop":
            status, body = 302, b"redirect"
            location = "/landed"
        elif path == "/landed":
            body = b"landed"
        elif path == "/cross":
            status, body = 302, b"redirect"
            location = self.cross_location or f"http://localhost:{port}/other"
        elif path == "/other":
            body = b"other"
        elif path == "/private-go":
            status, body = 302, b"redirect"
            location = "/private"
        elif path == "/private":
            body = b"private"
        elif path == "/secret":
            body = b"secret"
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


@pytest.fixture()
def redirect_server():
    _Handler.records = []
    _Handler.cross_location = ""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        _Handler.records = []


def _paths() -> list[str]:
    return [row["path"] for row in _Handler.records]


async def test_out_of_scope_redirect_is_not_requested(redirect_server):
    scope = Scope.from_config(redirect_server + "/out", ScanConfig())
    async with SafeHttpClient(scope, rate_limit=0, timeout=5) as client:
        response = await client.get(redirect_server + "/out")
    assert response.status == 302
    assert _paths() == ["/out"]
    assert "/secret" not in _paths()


async def test_in_scope_redirect_is_followed(redirect_server):
    scope = Scope.from_config(redirect_server + "/", ScanConfig())
    async with SafeHttpClient(scope, rate_limit=0, timeout=5) as client:
        response = await client.get(redirect_server + "/hop")
    assert response.status == 200
    assert response.text == "landed"
    assert _paths() == ["/hop", "/landed"]


async def test_follow_redirects_false_does_not_follow(redirect_server):
    scope = Scope.from_config(redirect_server + "/", ScanConfig())
    async with SafeHttpClient(scope, rate_limit=0, timeout=5, follow_redirects=False) as client:
        response = await client.get(redirect_server + "/hop")
    assert response.status == 302
    assert _paths() == ["/hop"]


async def test_per_request_follow_override(redirect_server):
    scope = Scope.from_config(redirect_server + "/", ScanConfig())
    async with SafeHttpClient(scope, rate_limit=0, timeout=5, follow_redirects=False) as client:
        skipped = await client.get(redirect_server + "/hop", follow_redirects=False)
        assert skipped.status == 302
        _Handler.records.clear()
        followed = await client.get(redirect_server + "/hop", follow_redirects=True)
    assert followed.status == 200
    assert followed.text == "landed"


async def test_excluded_path_redirect_is_not_requested(redirect_server):
    config = ScanConfig()
    config.scope.exclude = ["/private"]
    scope = Scope.from_config(redirect_server + "/", config)
    async with SafeHttpClient(scope, rate_limit=0, timeout=5) as client:
        response = await client.get(redirect_server + "/private-go")
    assert response.status == 302
    assert _paths() == ["/private-go"]


async def test_cross_origin_redirect_strips_authorization_and_keeps_allowed_cookie(redirect_server):
    # A different port is a different origin, still the same allowed host.
    other = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=other.serve_forever, daemon=True)
    thread.start()
    try:
        _Handler.cross_location = f"http://127.0.0.1:{other.server_address[1]}/other"
        scope = Scope.from_config(redirect_server + "/cross", ScanConfig())
        async with SafeHttpClient(
            scope,
            rate_limit=0,
            timeout=5,
            auth_headers={"Authorization": f"Bearer {_TOKEN}"},
            cookies={"session": "admintoken"},
        ) as client:
            response = await client.get(redirect_server + "/cross")
        assert response.status == 200
        assert response.text == "other"
        assert [row["path"] for row in _Handler.records] == ["/cross", "/other"]
        first, second = _Handler.records
        assert _TOKEN in first["authorization"]
        assert "admintoken" in first["cookie"]
        assert _TOKEN not in second["authorization"]
        assert "admintoken" in second["cookie"]
    finally:
        other.shutdown()
        other.server_close()


async def test_same_origin_redirect_keeps_authorization(redirect_server):
    scope = Scope.from_config(redirect_server + "/", ScanConfig())
    async with SafeHttpClient(
        scope,
        rate_limit=0,
        timeout=5,
        auth_headers={"Authorization": f"Bearer {_TOKEN}"},
    ) as client:
        response = await client.get(redirect_server + "/hop")
    assert response.status == 200
    first, second = _Handler.records
    assert _TOKEN in first["authorization"]
    assert _TOKEN in second["authorization"]
