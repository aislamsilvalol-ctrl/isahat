"""Tests for core models, severity ordering and risk prioritisation."""

from __future__ import annotations

from isahat.core.models import Confidence, Evidence, Finding, Severity
from isahat.core.risk import priority_score, sort_by_priority


def make_finding(title, severity, confidence, endpoint="https://x/", param=None) -> Finding:
    return Finding(
        title=title,
        category="test",
        severity=severity,
        confidence=confidence,
        endpoint=endpoint,
        parameter=param,
        evidence=Evidence(summary="s"),
        impact="i",
        recommendation="r",
    )


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank
    assert Severity.CRITICAL >= Severity.HIGH


def test_fingerprint_is_stable_and_unique():
    a = make_finding("Same", Severity.HIGH, Confidence.HIGH, param="p")
    b = make_finding("Same", Severity.HIGH, Confidence.HIGH, param="p")
    c = make_finding("Different", Severity.HIGH, Confidence.HIGH, param="p")
    assert a.id == b.id
    assert a.id != c.id
    assert a.id.startswith("ISA-")


def test_priority_confirmed_beats_possible():
    high_confirmed = make_finding("a", Severity.HIGH, Confidence.CONFIRMED)
    high_possible = make_finding("b", Severity.HIGH, Confidence.POSSIBLE)
    assert priority_score(high_confirmed) > priority_score(high_possible)


def test_false_positive_scores_zero():
    fp = make_finding("fp", Severity.CRITICAL, Confidence.FALSE_POSITIVE)
    assert priority_score(fp) == 0


def test_sort_by_priority_orders_desc():
    findings = [
        make_finding("low", Severity.LOW, Confidence.CONFIRMED),
        make_finding("crit", Severity.CRITICAL, Confidence.CONFIRMED),
        make_finding("med", Severity.MEDIUM, Confidence.HIGH),
    ]
    ordered = sort_by_priority(findings)
    assert [f.title for f in ordered] == ["crit", "med", "low"]
