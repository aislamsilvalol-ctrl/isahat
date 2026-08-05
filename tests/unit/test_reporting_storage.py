"""Tests for reporters, comparison and SQLite storage."""

from __future__ import annotations

from isahat.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    ScanResult,
    Severity,
    Technology,
)
from isahat.reporting import compare_scans, render, to_json, to_markdown
from isahat.reporting.compare import diff_to_markdown
from isahat.storage import ScanStore


def make_result(scan_id="abc123", findings=None) -> ScanResult:
    result = ScanResult(
        id=scan_id,
        target="https://example.com",
        scope={"target": "https://example.com", "allowed_hosts": ["example.com"]},
        endpoints=[Endpoint(url="https://example.com/", status=200)],
        technologies=[Technology(name="nginx", version="1.18.0", category="server")],
        findings=findings or [],
    )
    result.recompute_stats()
    return result


def sample_finding(title="Missing CSP", severity=Severity.MEDIUM) -> Finding:
    return Finding(
        title=title,
        category="Security Misconfiguration",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        endpoint="https://example.com/",
        evidence=Evidence(summary="no CSP header"),
        impact="XSS amplified",
        recommendation="Add a CSP",
    )


def test_json_report_roundtrips():
    result = make_result(findings=[sample_finding()])
    payload = to_json(result)
    restored = ScanResult.model_validate_json(payload)
    assert restored.id == result.id
    assert restored.findings[0].title == "Missing CSP"


def test_markdown_report_contains_sections():
    result = make_result(findings=[sample_finding()])
    md = to_markdown(result)
    assert "# IsaHat Security Audit" in md
    assert "## Executive summary" in md
    assert "## Findings" in md
    assert "Missing CSP" in md
    assert "confidence: confirmed" in md


def test_markdown_report_empty_findings():
    md = to_markdown(make_result())
    assert "No findings" in md


def test_render_unknown_format_raises():
    import pytest

    with pytest.raises(ValueError):
        render(make_result(), "xml")


def test_compare_detects_new_and_resolved():
    old = make_result("old", findings=[sample_finding("A")])
    new = make_result("new", findings=[sample_finding("B")])
    diff = compare_scans(old, new)
    assert len(diff.new) == 1 and diff.new[0].title == "B"
    assert len(diff.resolved) == 1 and diff.resolved[0].title == "A"
    assert "new" in diff_to_markdown(diff).lower()


def test_compare_detects_unchanged():
    finding = sample_finding("Persistent")
    old = make_result("old", findings=[finding])
    new = make_result("new", findings=[sample_finding("Persistent")])
    diff = compare_scans(old, new)
    assert len(diff.unchanged) == 1
    assert not diff.new and not diff.resolved


def test_storage_save_get_list(tmp_path):
    db = tmp_path / "isahat.db"
    result = make_result(findings=[sample_finding(severity=Severity.HIGH)])
    with ScanStore(db) as store:
        store.save(result)
        fetched = store.get(result.id)
        assert fetched is not None
        assert fetched.findings[0].title == "Missing CSP"
        rows = store.list()
        assert len(rows) == 1
        assert rows[0].high == 1
        assert store.get_latest_for_target("https://example.com").id == result.id


def test_storage_upsert_is_idempotent(tmp_path):
    db = tmp_path / "isahat.db"
    result = make_result()
    with ScanStore(db) as store:
        store.save(result)
        store.save(result)  # second save must not duplicate
        assert len(store.list()) == 1
        assert store.delete(result.id) is True
        assert store.get(result.id) is None
