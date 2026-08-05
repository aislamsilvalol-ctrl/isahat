"""Shared test helpers: synthetic responses and a fake HTTP client.

Tests are fully offline — no sockets. Detectors are exercised against
hand-built responses and a fake client that serves a fixed routing table.
"""

from __future__ import annotations

from collections.abc import Mapping

from isahat.core.config import ScanConfig
from isahat.core.http import HttpResponse
from isahat.core.scope import Scope


def make_response(
    url: str,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
    text: str = "",
    method: str = "GET",
) -> HttpResponse:
    return HttpResponse(
        url=url,
        status=status,
        headers=dict(headers or {}),
        text=text,
        elapsed_ms=1.0,
        request_method=method,
        request_headers={"User-Agent": "IsaHat/test"},
    )


def make_scope(target: str, allowed: list[str] | None = None) -> Scope:
    config = ScanConfig()
    if allowed:
        config.target.allowed_hosts = allowed
    return Scope.from_config(target, config)


class FakeClient:
    """A stand-in for :class:`SafeHttpClient` driven by a routing table.

    ``routes`` maps a URL path to an :class:`HttpResponse`. Unknown paths return
    a 404. It still enforces scope so tests catch accidental out-of-scope probes.
    """

    def __init__(self, scope: Scope, routes: dict[str, HttpResponse]) -> None:
        self._scope = scope
        self._routes = routes
        self.requests_made = 0

    async def get(self, url: str) -> HttpResponse:
        self._scope.require(url)
        self.requests_made += 1
        from urllib.parse import urlparse

        path = urlparse(url).path
        if path in self._routes:
            return self._routes[path]
        return make_response(url, status=404, text="not found")
