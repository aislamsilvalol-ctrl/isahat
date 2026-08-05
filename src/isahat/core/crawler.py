"""A small, polite, scope-bound crawler.

It performs a breadth-first walk starting from the target, only following links
that stay inside the authorised scope. It records every response so detectors
and technology fingerprinting can run against real captured traffic.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

from isahat.core.http import HttpResponse, SafeHttpClient
from isahat.core.models import Endpoint
from isahat.core.scope import Scope

# Anchor/src/action extraction. Deliberately simple and dependency-free.
_LINK_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)""",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class CrawlResult:
    responses: list[HttpResponse] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)


def _normalise(url: str) -> str:
    clean, _frag = urldefrag(url)
    return clean


def _same_document_asset(url: str) -> bool:
    """Skip obvious static assets to keep the crawl focused on app surface."""

    path = urlparse(url).path.lower()
    return path.endswith(
        (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf")
    )


class Crawler:
    def __init__(
        self,
        client: SafeHttpClient,
        scope: Scope,
        *,
        max_pages: int = 100,
        max_depth: int = 3,
    ) -> None:
        self._client = client
        self._scope = scope
        self._max_pages = max_pages
        self._max_depth = max_depth

    def _extract_links(self, base_url: str, body: str) -> set[str]:
        links: set[str] = set()
        for match in _LINK_RE.finditer(body):
            raw = match.group(1).strip()
            if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = _normalise(urljoin(base_url, raw))
            links.add(absolute)
        return links

    async def crawl(self, start_url: str) -> CrawlResult:
        result = CrawlResult()
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(_normalise(start_url), 0)])
        recorded: set[tuple[str, str]] = set()

        while queue and len(result.responses) < self._max_pages:
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            if not self._scope.allows(url):
                continue

            try:
                response = await self._client.get(url)
            except Exception:  # noqa: BLE001 - network errors must not abort the crawl
                continue

            result.responses.append(response)
            title = None
            title_match = _TITLE_RE.search(response.text) if response.text else None
            if title_match:
                title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120]

            endpoint = Endpoint(
                url=response.url,
                method="GET",
                status=response.status,
                content_type=response.headers.get("content-type"),
                title=title,
            )
            if endpoint.key() not in recorded:
                recorded.add(endpoint.key())
                result.endpoints.append(endpoint)

            content_type = (response.headers.get("content-type") or "").lower()
            if depth >= self._max_depth or "html" not in content_type:
                continue

            for link in self._extract_links(response.url, response.text):
                if link in seen or _same_document_asset(link):
                    continue
                if self._scope.allows(link):
                    queue.append((link, depth + 1))
                elif self._scope.host_allowed(urlparse(link).hostname):
                    # In-scope host but excluded path: record as surface, never fetch.
                    off = Endpoint(
                        url=link,
                        method="GET",
                        discovered_from=response.url,
                        status=None,
                    )
                    if off.key() not in recorded:
                        recorded.add(off.key())
                        result.endpoints.append(off)

        return result
