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

    ``routes`` maps a URL path to either an :class:`HttpResponse` or a callable
    ``(url, headers) -> HttpResponse`` for responses that depend on the request
    (e.g. CORS Origin reflection or query-dependent reflection). Unknown paths
    return a 404. Scope is enforced so tests catch out-of-scope probes.
    """

    def __init__(self, scope: Scope, routes: dict[str, object]) -> None:
        self._scope = scope
        self._routes = routes
        self.requests_made = 0

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool | None = None,
    ) -> HttpResponse:
        self._scope.require(url)
        self.requests_made += 1
        from urllib.parse import urlparse

        path = urlparse(url).path or "/"
        route = self._routes.get(path)
        if route is None:
            return make_response(url, status=404, text="not found")
        if callable(route):
            return route(url, headers or {})
        assert isinstance(route, HttpResponse)
        return route
