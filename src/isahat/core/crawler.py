"""A small, polite, scope-bound crawler.

It performs a breadth-first walk starting from the target, only following links
that stay inside the authorised scope. It records every response so detectors
and technology fingerprinting can run against real captured traffic.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from isahat.core.http import HttpResponse, SafeHttpClient
from isahat.core.models import DiscoveredForm, Endpoint
from isahat.core.scope import Scope

# Anchor/src/action extraction. Deliberately simple and dependency-free.
_LINK_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)""",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FORM_ATTR_RE = re.compile(r"""(\w+)\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(
    r"""<(?:input|textarea|select)\b[^>]*?\bname\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class CrawlResult:
    responses: list[HttpResponse] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)


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

    def _extract_forms(self, base_url: str, body: str) -> list[DiscoveredForm]:
        forms: list[DiscoveredForm] = []
        for match in _FORM_RE.finditer(body):
            tag = body[match.start() : match.start() + match.group(0).find(">") + 1]
            attrs = {k.lower(): v for k, v in _FORM_ATTR_RE.findall(tag)}
            method = (attrs.get("method") or "GET").upper()
            action = _normalise(urljoin(base_url, attrs.get("action") or base_url))
            names = list(dict.fromkeys(_INPUT_NAME_RE.findall(match.group(1))))
            forms.append(
                DiscoveredForm(page_url=base_url, action=action, method=method, params=names)
            )
        return forms

    async def crawl(self, start_url: str) -> CrawlResult:
        result = CrawlResult()
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(_normalise(start_url), 0)])
        recorded: set[tuple[str, str]] = set()
        recorded_forms: set[tuple[str, str]] = set()

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

            # Record the *requested* URL (with its query) rather than the final
            # redirected URL, so parameters survive redirects for later testing.
            query = urlparse(url).query
            params = list(parse_qs(query).keys()) if query else []
            endpoint = Endpoint(
                url=url,
                method="GET",
                status=response.status,
                content_type=response.headers.get("content-type"),
                title=title,
                params=params,
            )
            if endpoint.key() not in recorded:
                recorded.add(endpoint.key())
                result.endpoints.append(endpoint)

            content_type = (response.headers.get("content-type") or "").lower()
            if depth >= self._max_depth or "html" not in content_type:
                continue

            for form in self._extract_forms(response.url, response.text):
                if form.key() not in recorded_forms and self._scope.allows(form.action):
                    recorded_forms.add(form.key())
                    result.forms.append(form)

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
