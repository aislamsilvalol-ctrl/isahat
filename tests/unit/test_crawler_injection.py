"""Tests for form/parameter discovery and injection-point collection."""

from __future__ import annotations

from isahat.core.crawler import Crawler
from isahat.core.injection import InjectionPoint, collect_get_points
from tests.unit.helpers import FakeClient, make_response, make_scope

_HTML = """
<html><body>
  <a href="/search?q=hello">search</a>
  <a href="/item?id=1&sort=asc">item</a>
  <form action="/login" method="post">
    <input name="username"><input name="password">
  </form>
  <form action="/find" method="get">
    <input name="term"><select name="cat"></select>
  </form>
</body></html>
"""


async def test_crawler_extracts_params_and_forms():
    target = "https://example.com"
    scope = make_scope(target)
    routes = {
        "/": make_response(target + "/", headers={"content-type": "text/html"}, text=_HTML),
        "/search": make_response(
            target + "/search?q=hello", headers={"content-type": "text/html"}, text="ok"
        ),
        "/item": make_response(
            target + "/item?id=1&sort=asc", headers={"content-type": "text/html"}, text="ok"
        ),
        "/find": make_response(target + "/find", headers={"content-type": "text/html"}, text="ok"),
    }
    # The crawler needs a client that returns the linked pages; FakeClient maps by path.
    client = FakeClient(scope, routes)
    crawler = Crawler(client, scope, max_pages=10, max_depth=2)
    result = await crawler.crawl(target)

    form_actions = {(f.method, f.action.split("example.com")[-1]) for f in result.forms}
    assert ("POST", "/login") in form_actions
    assert ("GET", "/find") in form_actions
    login = next(f for f in result.forms if f.action.endswith("/login"))
    assert set(login.params) == {"username", "password"}


def test_injection_points_from_urls_and_forms():
    from isahat.core.models import DiscoveredForm

    urls = [
        "https://example.com/search?q=hello",
        "https://example.com/item?id=1&sort=asc",
        "https://example.com/static",  # no params -> ignored
    ]
    forms = [
        DiscoveredForm(
            page_url="https://example.com/",
            action="https://example.com/find",
            method="GET",
            params=["term"],
        ),
        DiscoveredForm(
            page_url="https://example.com/",
            action="https://example.com/login",
            method="POST",  # POST excluded from safe GET points
            params=["username"],
        ),
    ]
    points = collect_get_points(urls, forms)
    params = {(p.url.split("example.com")[-1], p.param) for p in points}
    assert ("/search", "q") in params
    assert ("/item", "id") in params
    assert ("/item", "sort") in params
    assert ("/find", "term") in params
    assert all(p.method == "GET" for p in points)
    # POST form parameter must not appear.
    assert ("/login", "username") not in params


def test_injection_point_build_url_overrides_param():
    point = InjectionPoint(
        url="https://example.com/item",
        method="GET",
        param="id",
        base_params=(("id", "1"), ("sort", "asc")),
    )
    built = point.build_url("PAYLOAD")
    assert "id=PAYLOAD" in built
    assert "sort=asc" in built


def test_collect_respects_limit():
    urls = [f"https://example.com/p?a{i}=1&b{i}=2" for i in range(50)]
    points = collect_get_points(urls, [], limit=10)
    assert len(points) == 10
