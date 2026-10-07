"""A safe, rate-limited, scope-aware HTTP client.

Every outbound request goes through :class:`SafeHttpClient`, which:

* refuses any URL outside the authorised :class:`~isahat.core.scope.Scope`;
* throttles requests per host to the configured rate limit;
* only issues non-destructive methods unless destructive tests are explicitly
  enabled (which the MVP never does);
* identifies itself honestly via the ``User-Agent`` (no evasion);
* follows redirects itself and checks every hop against the scope, so an
  out-of-scope ``Location`` is never requested.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from isahat import __version__
from isahat.core.scope import Scope

USER_AGENT = f"IsaHat/{__version__} (+https://github.com/aislamsilvalol-ctrl/isahat; authorized-scan)"

# Methods considered non-destructive and therefore always allowed.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Status codes httpx follows. 300 is left alone, matching that client.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 20
_AUTH_HEADER_NAMES = frozenset({"authorization", "proxy-authorization"})


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if parsed.port is not None:
        port = parsed.port
    elif scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        port = 0
    return scheme, host, port


def _same_origin(left: str, right: str) -> bool:
    return _origin(left) == _origin(right)


def _is_https_upgrade(src: str, dst: str) -> bool:
    """True for http://host -> https://host on the default ports.

    httpx keeps ``Authorization`` across that one upgrade and strips it on
    every other origin change. The manual redirect loop does the same.
    """

    src_origin, dst_origin = _origin(src), _origin(dst)
    return (
        src_origin[1] == dst_origin[1]
        and src_origin[0] == "http"
        and src_origin[2] == 80
        and dst_origin[0] == "https"
        and dst_origin[2] == 443
    )


def _redirect_method(method: str, status: int) -> str:
    if status in (302, 303) and method != "HEAD":
        return "GET"
    if status == 301 and method == "POST":
        return "GET"
    return method


def _resolve_redirect(current: str, location: str) -> str:
    """Resolve a ``Location`` the same way httpx does, without requesting it."""

    try:
        url = httpx.URL(location)
    except httpx.InvalidURL:
        return location
    base = httpx.URL(current)
    if url.scheme and not url.host:
        url = url.copy_with(host=base.host)
    if url.is_relative_url:
        url = base.join(url)
    if base.fragment and not url.fragment:
        url = url.copy_with(fragment=base.fragment)
    return str(url)


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
        self._follow_redirects = follow_redirects
        self._auth_headers = dict(auth_headers or {})
        self._limiter = _HostRateLimiter(rate_limit)
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        # Auth cookies are bound to allowed hosts so a redirect cannot carry
        # them to some other domain. httpx follows redirects itself only when
        # we ask; we never do — each hop is checked below.
        jar = httpx.Cookies()
        for host in scope.allowed_hosts:
            for name, value in (cookies or {}).items():
                jar.set(name, value, domain=host, path="/")
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            cookies=jar,
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

        When following, each ``Location`` is checked with the scope before the
        next request. An out-of-scope hop is not sent; the redirect response
        already received is returned instead.
        """

        self._scope.require(url)
        self._check_method(method)
        follow = self._follow_redirects if follow_redirects is None else follow_redirects
        async with self._semaphore:
            started = time.perf_counter()
            response = await self._exchange(method.upper(), url, headers, follow=follow)
            elapsed_ms = (time.perf_counter() - started) * 1000
        return HttpResponse(
            url=str(response.url),
            status=response.status_code,
            headers=dict(response.headers.items()),
            text=response.text,
            elapsed_ms=elapsed_ms,
            request_method=method.upper(),
            request_headers=dict(response.request.headers.items()),
        )

    def _outbound_headers(
        self, extra: dict[str, str] | None, *, include_authorization: bool
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        if include_authorization:
            headers.update(self._auth_headers)
        if extra:
            headers.update(extra)
        if not include_authorization:
            headers = {
                name: value
                for name, value in headers.items()
                if name.lower() not in _AUTH_HEADER_NAMES
            }
        return headers

    async def _exchange(
        self,
        method: str,
        url: str,
        extra_headers: dict[str, str] | None,
        *,
        follow: bool,
    ) -> httpx.Response:
        """Send ``url``, following in-scope redirects up to ``_MAX_REDIRECTS``."""

        current_url = url
        current_method = method
        extra = dict(extra_headers or {})
        include_authorization = True
        for hop in range(_MAX_REDIRECTS + 1):
            host = urlparse(current_url).hostname or ""
            await self._limiter.acquire(host)
            headers = self._outbound_headers(
                extra, include_authorization=include_authorization
            )
            kwargs: dict[str, object] = {}
            if headers:
                kwargs["headers"] = headers
            response = await self._send_with_retry(current_method, current_url, kwargs)
            self.requests_made += 1
            if not follow or response.status_code not in _REDIRECT_STATUSES:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            next_url = _resolve_redirect(str(response.url), location)
            if not self._scope.allows(next_url):
                return response
            if hop == _MAX_REDIRECTS:
                raise httpx.TooManyRedirects("Exceeded maximum allowed redirects.")
            current_method = _redirect_method(current_method, response.status_code)
            self._check_method(current_method)
            landed = str(response.url)
            include_authorization = _same_origin(landed, next_url) or _is_https_upgrade(
                landed, next_url
            )
            extra = {
                name: value
                for name, value in extra.items()
                if name.lower() not in {"cookie", *_AUTH_HEADER_NAMES}
            }
            current_url = next_url
        raise httpx.TooManyRedirects("Exceeded maximum allowed redirects.")

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
