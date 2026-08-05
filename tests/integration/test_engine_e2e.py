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


def test_scope_blocks_out_of_scope_target(lab_server):
    engine = ScanEngine(lab_server, _config())
    # A different host must not be reachable through the engine's client/scope.
    assert not engine.scope.allows("https://example.com/")
