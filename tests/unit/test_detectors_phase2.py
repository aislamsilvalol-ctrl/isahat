"""Tests for the Phase 2 safe active detectors."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from isahat.core.detectors.base import DetectorContext
from isahat.core.detectors.cors import CorsDetector
from isahat.core.detectors.open_redirect import OpenRedirectDetector
from isahat.core.detectors.reflected_xss import ReflectedXssDetector
from isahat.core.detectors.sqli_error import SqlInjectionErrorDetector
from isahat.core.injection import InjectionPoint
from isahat.core.models import Confidence, Severity
from tests.unit.helpers import FakeClient, make_response, make_scope

TARGET = "https://example.com"


def ctx_with(routes, points=None, responses=None):
    scope = make_scope(TARGET)
    client = FakeClient(scope, routes)
    return DetectorContext(
        target=TARGET,
        scope=scope,
        client=client,
        responses=responses or [],
        injection_points=points or [],
    )


# --- CORS ---------------------------------------------------------------

async def test_cors_reflects_arbitrary_origin_with_credentials():
    def api(url, headers):
        origin = headers.get("Origin", "*")
        return make_response(
            url,
            headers={
                "content-type": "application/json",
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            },
            text="{}",
        )

    ctx = ctx_with(
        routes={"/api/users": api},
        responses=[make_response(TARGET + "/api/users", headers={"content-type": "application/json"})],
    )
    findings = await CorsDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == Confidence.CONFIRMED


async def test_cors_wildcard_only_is_low():
    def api(url, headers):
        return make_response(
            url,
            headers={"content-type": "application/json", "access-control-allow-origin": "*"},
            text="{}",
        )

    ctx = ctx_with(
        routes={"/api/users": api},
        responses=[make_response(TARGET + "/api/users", headers={"content-type": "application/json"})],
    )
    findings = await CorsDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


async def test_cors_no_header_no_finding():
    ctx = ctx_with(
        routes={"/api/users": make_response(TARGET + "/api/users", text="{}")},
        responses=[make_response(TARGET + "/api/users")],
    )
    assert await CorsDetector().run(ctx) == []


# --- Open redirect ------------------------------------------------------

async def test_open_redirect_detected():
    def go(url, headers):
        target = parse_qs(urlparse(url).query).get("url", [""])[0]
        return make_response(url, status=302, headers={"location": target})

    point = InjectionPoint(url=TARGET + "/go", method="GET", param="url", base_params=(("url", "/"),))
    ctx = ctx_with(routes={"/go": go}, points=[point])
    findings = await OpenRedirectDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].parameter == "url"


async def test_open_redirect_ignores_same_host_redirect():
    def go(url, headers):
        # Always redirects internally, regardless of the parameter.
        return make_response(url, status=302, headers={"location": "/home"})

    point = InjectionPoint(url=TARGET + "/go", method="GET", param="url", base_params=(("url", "/"),))
    ctx = ctx_with(routes={"/go": go}, points=[point])
    assert await OpenRedirectDetector().run(ctx) == []


# --- Reflected XSS ------------------------------------------------------

async def test_reflected_xss_detected_when_unencoded():
    def search(url, headers):
        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        return make_response(
            url, headers={"content-type": "text/html"}, text=f"<html>Results: {q}</html>"
        )

    point = InjectionPoint(url=TARGET + "/search", method="GET", param="q", base_params=(("q", "x"),))
    ctx = ctx_with(routes={"/search": search}, points=[point])
    findings = await ReflectedXssDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].parameter == "q"


async def test_reflected_xss_not_flagged_when_encoded():
    def search(url, headers):
        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        encoded = q.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        return make_response(
            url, headers={"content-type": "text/html"}, text=f"<html>Results: {encoded}</html>"
        )

    point = InjectionPoint(url=TARGET + "/search", method="GET", param="q", base_params=(("q", "x"),))
    ctx = ctx_with(routes={"/search": search}, points=[point])
    assert await ReflectedXssDetector().run(ctx) == []


# --- SQL injection (error-based) ---------------------------------------

async def test_sqli_error_detected():
    def item(url, headers):
        item_id = parse_qs(urlparse(url).query).get("id", [""])[0]
        if "'" in item_id:
            return make_response(
                url,
                status=500,
                headers={"content-type": "text/plain"},
                text="You have an error in your SQL syntax near \"'\"",
            )
        return make_response(url, headers={"content-type": "application/json"}, text="{}")

    point = InjectionPoint(url=TARGET + "/item", method="GET", param="id", base_params=(("id", "1"),))
    ctx = ctx_with(routes={"/item": item}, points=[point])
    findings = await SqlInjectionErrorDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == Confidence.PROBABLE


async def test_sqli_no_error_no_finding():
    def item(url, headers):
        return make_response(url, headers={"content-type": "application/json"}, text='{"ok":1}')

    point = InjectionPoint(url=TARGET + "/item", method="GET", param="id", base_params=(("id", "1"),))
    ctx = ctx_with(routes={"/item": item}, points=[point])
    assert await SqlInjectionErrorDetector().run(ctx) == []
