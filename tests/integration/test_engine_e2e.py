"""End-to-end engine test against the bundled vulnerable lab app.

Starts the stdlib lab server on a loopback port (no external network) and runs
a full scan through the real engine, crawler, HTTP client and detectors.
"""

from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from isahat.core.config import ScanConfig
from isahat.core.engine import ScanEngine
from isahat.core.models import Severity

_LAB_APP = (
    Path(__file__).resolve().parents[2]
    / "labs"
    / "vulnerable_apps"
    / "simple_app"
    / "app.py"
)


def _load_handler():
    spec = importlib.util.spec_from_file_location("isahat_lab_app", _LAB_APP)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VulnerableHandler


@pytest.fixture()
def lab_server():
    handler = _load_handler()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _config() -> ScanConfig:
    config = ScanConfig()
    config.safety.require_scope_confirmation = False
    config.safety.rate_limit = 0  # no throttling for the loopback test
    config.scan.max_pages = 20
    return config


def test_full_scan_finds_expected_issues(lab_server):
    engine = ScanEngine(lab_server, _config())
    result = engine.scan()

    # Surface discovery
    urls = {e.url for e in result.endpoints}
    assert any(u.rstrip("/").endswith("/dashboard") for u in urls)
    assert result.stats.requests_made > 0

    titles = " ".join(f.title for f in result.findings)
    # Headers
    assert "Content-Security-Policy" in titles
    # Cookies
    assert any("cookie" in f.title.lower() for f in result.findings)
    # Sensitive files (.env is CRITICAL)
    env_findings = [f for f in result.findings if ".env" in f.endpoint]
    assert env_findings and env_findings[0].severity == Severity.CRITICAL

    # Technology fingerprinting picked up the generator meta tag.
    tech_names = {t.name.lower() for t in result.technologies}
    assert any("labcms" in name or "lab" in name for name in tech_names)

    # Findings are sorted by priority (critical first).
    assert result.findings[0].severity == Severity.CRITICAL

    # Secrets never leak into evidence.
    for finding in result.findings:
        assert "sk_live_abc123" not in (finding.evidence.response or "")


def test_phase2_active_detectors_find_param_issues(lab_server):
    engine = ScanEngine(lab_server, _config())
    result = engine.scan()

    categories = {f.category for f in result.findings}
    # Forms are discovered from the dashboard.
    assert result.stats.forms_discovered >= 1

    # Reflected XSS on /search?q=
    assert "Cross-Site Scripting" in categories
    # Open redirect on /go?url=
    assert "Open Redirect" in categories
    # Error-based SQLi on /item?id='
    assert "Injection" in categories
    # Insecure CORS on /api/users (reflects Origin + credentials)
    cors = [f for f in result.findings if f.category == "Security Misconfiguration"
            and "CORS" in f.title]
    assert cors and cors[0].severity in (Severity.HIGH, Severity.MEDIUM)
    # Path traversal on /download?file=
    assert "Path Traversal" in categories


def test_api_surface_discovery_and_api_detectors(lab_server):
    engine = ScanEngine(lab_server, _config())
    result = engine.scan()

    # Both the OpenAPI document and the GraphQL endpoint are discovered.
    kinds = {a.kind for a in result.apis}
    assert {"rest", "graphql"} <= kinds
    assert result.stats.apis_discovered == len(result.apis)
    rest = next(a for a in result.apis if a.kind == "rest")
    assert rest.title == "Lab API"
    assert any("GET /api/users" in op for op in rest.operations)

    api_findings = [f for f in result.findings if f.category == "API Security"]
    titles = " ".join(f.title for f in api_findings)
    # Introspection left enabled on /graphql.
    assert "introspection" in titles.lower()
    # password_hash leaked by /api/users.
    assert "Sensitive data exposed" in titles
    # Leaked values are masked in evidence.
    for finding in api_findings:
        assert "$2b$12$abc" not in (finding.evidence.response or "")


def test_scope_blocks_out_of_scope_target(lab_server):
    engine = ScanEngine(lab_server, _config())
    # A different host must not be reachable through the engine's client/scope.
    assert not engine.scope.allows("https://example.com/")


async def test_authenticated_client_attaches_cookies(lab_server):
    # The lab's /whoami echoes whether the admin session cookie arrived; this
    # verifies the auth material actually reaches the target through the client.
    from isahat.core.auth import AuthConfig
    from isahat.core.http import SafeHttpClient
    from isahat.core.scope import Scope

    config = _config()
    scope = Scope.from_config(lab_server, config)
    auth = AuthConfig(cookies={"session": "admintoken"})
    async with SafeHttpClient(
        scope, rate_limit=0, auth_headers=auth.headers, cookies=auth.cookies
    ) as client:
        response = await client.get(lab_server + "/whoami")
    assert '"auth": true' in response.text


def test_authenticated_scan_sets_flag(lab_server):
    from isahat.core.auth import AuthConfig

    engine = ScanEngine(lab_server, _config(), auth=AuthConfig(cookies={"session": "admintoken"}))
    result = engine.scan()
    assert result.authenticated is True
