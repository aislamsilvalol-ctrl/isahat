"""A safe, rate-limited, scope-aware HTTP client.

Every outbound request goes through :class:`SafeHttpClient`, which:

* refuses any URL outside the authorised :class:`~isahat.core.scope.Scope`;
* throttles requests per host to the configured rate limit;
* only issues non-destructive methods unless destructive tests are explicitly
  enabled (which the MVP never does);
* identifies itself honestly via the ``User-Agent`` (no evasion).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from isahat import __version__
from isahat.core.scope import Scope

USER_AGENT = f"IsaHat/{__version__} (+https://github.com/isahat/isahat; authorized-scan)"

# Methods considered non-destructive and therefore always allowed.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class HttpResponse:
    """A minimal, engine-friendly view of an HTTP response.

    Header names are normalised to lower-case (HTTP headers are
    case-insensitive) so detectors can look them up consistently.
    """

    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    request_method: str
    request_headers: dict[str, str]

    def __post_init__(self) -> None:
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        self.request_headers = {k.lower(): v for k, v in self.request_headers.items()}


class _HostRateLimiter:
    """Simple async token spacing: at most ``rate`` requests/sec per host."""

    def __init__(self, rate: float) -> None:
        self._min_interval = 1.0 / rate if rate > 0 else 0.0
        self._last: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, host: str) -> asyncio.Lock:
        if host not in self._locks:
            self._locks[host] = asyncio.Lock()
        return self._locks[host]

    async def acquire(self, host: str) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock_for(host):
            now = time.monotonic()
            last = self._last.get(host, 0.0)
            wait = self._min_interval - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last[host] = time.monotonic()


class SafeHttpClient:
    """Async HTTP client bound to a scope and safety settings."""

    def __init__(
        self,
        scope: Scope,
        *,
        timeout: float = 10.0,
        rate_limit: float = 3.0,
        follow_redirects: bool = True,
        destructive: bool = False,
        concurrency: int = 5,
        auth_headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self._scope = scope
        self._destructive = destructive
        self._limiter = _HostRateLimiter(rate_limit)
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        headers = {"User-Agent": USER_AGENT}
        if auth_headers:
            headers.update(auth_headers)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers=headers,
            cookies=cookies or None,
        )
        self.requests_made = 0

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _check_method(self, method: str) -> None:
        upper = method.upper()
        if upper not in SAFE_METHODS and not self._destructive:
            raise PermissionError(
                f"method {upper} is destructive and not allowed by the current profile"
            )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool | None = None,
    ) -> HttpResponse:
        """Perform a scoped, rate-limited request. Raises on scope/method violations.

        ``headers`` adds request headers for controlled probes (e.g. an ``Origin``
        for CORS checks). ``follow_redirects`` overrides the client default for a
        single request — detectors that inspect ``Location`` (open redirect) pass
        ``False`` so the redirect is observed rather than followed.
        """

        self._scope.require(url)
        self._check_method(method)
        host = urlparse(url).hostname or ""
        kwargs: dict[str, object] = {}
        if headers:
            kwargs["headers"] = headers
        if follow_redirects is not None:
            kwargs["follow_redirects"] = follow_redirects
        async with self._semaphore:
            await self._limiter.acquire(host)
            started = time.perf_counter()
            response = await self._send_with_retry(method.upper(), url, kwargs)
            elapsed_ms = (time.perf_counter() - started) * 1000
        self.requests_made += 1
        return HttpResponse(
            url=str(response.url),
            status=response.status_code,
            headers=dict(response.headers.items()),
            text=response.text,
            elapsed_ms=elapsed_ms,
            request_method=method.upper(),
            request_headers=dict(response.request.headers.items()),
        )

    async def _send_with_retry(
        self, method: str, url: str, kwargs: dict[str, object]
    ) -> httpx.Response:
        """Issue the request, retrying once on a transient transport error.

        Safe methods are idempotent, so a single retry after a dropped
        connection (common with keep-alive under bursty load) is harmless and
        makes real-world scans over flaky networks more reliable.
        """

        try:
            return await self._client.request(method, url, **kwargs)  # type: ignore[arg-type]
        except httpx.TransportError:
            await asyncio.sleep(0.1)
            return await self._client.request(method, url, **kwargs)  # type: ignore[arg-type]

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool | None = None,
    ) -> HttpResponse:
        return await self.request(
            "GET", url, headers=headers, follow_redirects=follow_redirects
        )
