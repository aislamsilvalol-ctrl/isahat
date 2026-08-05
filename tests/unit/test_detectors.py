"""Tests for the built-in detectors."""

from __future__ import annotations

from isahat.core.detectors.base import DetectorContext
from isahat.core.detectors.cookies import CookieSecurityDetector
from isahat.core.detectors.security_headers import SecurityHeadersDetector
from isahat.core.detectors.sensitive_files import SensitiveFilesDetector
from isahat.core.models import Confidence, Severity
from tests.unit.helpers import FakeClient, make_response, make_scope


def build_ctx(target, responses, routes=None):
    scope = make_scope(target)
    client = FakeClient(scope, routes or {})
    return DetectorContext(target=target, scope=scope, client=client, responses=responses)


async def test_security_headers_flags_missing_headers():
    target = "https://example.com"
    responses = [make_response(target + "/", headers={"Content-Type": "text/html"}, text="<html></html>")]
    ctx = build_ctx(target, responses)

    findings = await SecurityHeadersDetector().run(ctx)
    titles = {f.title for f in findings}

    assert any("Content-Security-Policy" in t for t in titles)
    assert any("Strict-Transport-Security" in t for t in titles)
    assert all(f.confidence == Confidence.CONFIRMED for f in findings)


async def test_security_headers_clean_when_all_present():
    target = "https://example.com"
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    ctx = build_ctx(target, [make_response(target + "/", headers=headers, text="<html></html>")])
    findings = await SecurityHeadersDetector().run(ctx)
    assert findings == []


async def test_version_disclosure_is_info():
    target = "https://example.com"
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=1",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Server": "nginx/1.18.0",
    }
    ctx = build_ctx(target, [make_response(target + "/", headers=headers, text="<html></html>")])
    findings = await SecurityHeadersDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "version" in findings[0].title.lower()


async def test_insecure_cookie_detected():
    target = "https://example.com"
    responses = [
        make_response(
            target + "/",
            headers={"Content-Type": "text/html", "Set-Cookie": "session=secretvalue; Path=/"},
        )
    ]
    ctx = build_ctx(target, responses)
    findings = await CookieSecurityDetector().run(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.parameter == "session"
    assert finding.severity == Severity.MEDIUM  # missing Secure on https
    # Value must never leak into evidence.
    assert "secretvalue" not in (finding.evidence.response or "")


async def test_secure_cookie_not_flagged():
    target = "https://example.com"
    responses = [
        make_response(
            target + "/",
            headers={"Set-Cookie": "session=x; Secure; HttpOnly; SameSite=Lax"},
        )
    ]
    ctx = build_ctx(target, responses)
    findings = await CookieSecurityDetector().run(ctx)
    assert findings == []


async def test_sensitive_files_detects_env():
    target = "http://127.0.0.1"
    env_body = "DATABASE_URL=postgres://user:pass@localhost/db\nAPI_KEY=sk_live_x\n"
    routes = {"/.env": make_response(target + "/.env", text=env_body, headers={"Content-Type": "text/plain"})}
    ctx = build_ctx(target, [], routes=routes)
    findings = await SensitiveFilesDetector().run(ctx)
    env_findings = [f for f in findings if ".env" in f.endpoint]
    assert env_findings, "expected an .env finding"
    finding = env_findings[0]
    assert finding.severity == Severity.CRITICAL
    # Secrets in the body must be redacted in the stored evidence.
    assert "sk_live_x" not in (finding.evidence.response or "")


async def test_sensitive_files_ignores_html_fallback():
    target = "http://127.0.0.1"
    html = "<!doctype html><html><body>Not found</body></html>"
    routes = {"/.env": make_response(target + "/.env", text=html, headers={"Content-Type": "text/html"})}
    ctx = build_ctx(target, [], routes=routes)
    findings = await SensitiveFilesDetector().run(ctx)
    assert [f for f in findings if ".env" in f.endpoint] == []
