"""Discovery of safe injection points for parameter-level testing.

An *injection point* is a single parameter that IsaHat can vary to observe how
the application responds. To stay non-destructive by default, only **GET**
points are collected here — query-string parameters seen during crawling and
parameters of GET forms. POST/state-changing forms are intentionally excluded
from the safe profile.

The number of points is capped so a scan never generates unbounded traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from isahat.core.models import DiscoveredForm

DEFAULT_MAX_POINTS = 40


@dataclass(frozen=True)
class InjectionPoint:
    """A single GET parameter that can be safely varied for testing."""

    url: str  # base URL without the query string
    method: str
    param: str
    base_params: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    source: str = "query"  # "query" | "form"

    def build_url(self, value: str) -> str:
        """Return ``url`` with all base params, overriding ``param`` with ``value``."""

        merged: dict[str, str] = dict(self.base_params)
        merged[self.param] = value
        parsed = urlparse(self.url)
        query = urlencode(merged)
        return urlunparse(parsed._replace(query=query))

    def key(self) -> tuple[str, str, str]:
        path = urlparse(self.url).path
        return (self.method.upper(), path, self.param)


def _points_from_url(url: str) -> list[InjectionPoint]:
    parsed = urlparse(url)
    if not parsed.query:
        return []
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    base_url = urlunparse(parsed._replace(query=""))
    base_params = tuple(pairs)
    return [
        InjectionPoint(url=base_url, method="GET", param=name, base_params=base_params)
        for name, _value in pairs
    ]


def _points_from_form(form: DiscoveredForm) -> list[InjectionPoint]:
    if form.method.upper() != "GET" or not form.params:
        return []
    base_params = tuple((name, "test") for name in form.params)
    parsed = urlparse(form.action)
    base_url = urlunparse(parsed._replace(query=""))
    return [
        InjectionPoint(
            url=base_url, method="GET", param=name, base_params=base_params, source="form"
        )
        for name in form.params
    ]


def collect_get_points(
    urls: list[str],
    forms: list[DiscoveredForm],
    *,
    limit: int = DEFAULT_MAX_POINTS,
) -> list[InjectionPoint]:
    """Gather de-duplicated, capped GET injection points from discovered URLs.

    ``urls`` are the requested URLs seen during crawling (which retain their
    query strings even when the response was a redirect).
    """

    seen: set[tuple[str, str, str]] = set()
    points: list[InjectionPoint] = []

    def add(candidates: list[InjectionPoint]) -> None:
        for point in candidates:
            if len(points) >= limit:
                return
            key = point.key()
            if key in seen:
                continue
            seen.add(key)
            points.append(point)

    for url in urls:
        add(_points_from_url(url))
    for form in forms:
        add(_points_from_form(form))

    return points
