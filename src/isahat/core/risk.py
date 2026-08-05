"""Risk prioritisation — turning severity + confidence into a fix order.

IsaHat keeps severity and confidence separate (see :mod:`isahat.core.models`).
The priority score combines them so developers know what to fix first without
losing the nuance that a scary-but-unconfirmed finding is not the same as a
confirmed one.
"""

from __future__ import annotations

from isahat.core.models import Confidence, Finding, Severity

# Base weight from severity.
_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 70,
    Severity.MEDIUM: 40,
    Severity.LOW: 15,
    Severity.INFO: 5,
}

# Multiplier from confidence.
_CONFIDENCE_FACTOR: dict[Confidence, float] = {
    Confidence.CONFIRMED: 1.0,
    Confidence.HIGH: 0.85,
    Confidence.PROBABLE: 0.65,
    Confidence.POSSIBLE: 0.45,
    Confidence.FALSE_POSITIVE: 0.0,
}


def priority_score(finding: Finding) -> int:
    """Return an integer 0–100 combining severity and confidence."""

    weight = _SEVERITY_WEIGHT[finding.severity]
    factor = _CONFIDENCE_FACTOR[finding.confidence]
    return round(weight * factor)


def sort_by_priority(findings: list[Finding]) -> list[Finding]:
    """Highest priority first; ties broken by severity then title for stability."""

    return sorted(
        findings,
        key=lambda f: (-priority_score(f), -f.severity.rank, f.title),
    )
