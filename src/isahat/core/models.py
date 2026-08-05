"""Core data contracts shared across the whole engine.

These models are the stable interface between the scanner, the storage layer,
the reporters and every front-end. They are intentionally serialisable so a
scan can be persisted, re-loaded and compared without loss.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(str, Enum):
    """Impact of a finding if exploited. Ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    # Intentional override: compare by security rank, not string value, so
    # ``Severity.CRITICAL >= Severity.HIGH`` reads naturally. This deviates from
    # ``str.__ge__`` on purpose (hence the override suppression).
    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """How sure IsaHat is that the finding is real. Kept separate from severity.

    A finding can be ``CRITICAL`` severity with ``POSSIBLE`` confidence — the
    reporter always shows both so nothing is ever overstated.
    """

    POSSIBLE = "possible"
    PROBABLE = "probable"
    HIGH = "high"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class FindingState(str, Enum):
    """Lifecycle of a finding across scans and reviews."""

    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"


class Evidence(BaseModel):
    """Sanitised proof for a finding.

    ``request`` and ``response`` hold already-masked text. Raw secrets must
    never be stored here — masking happens before the evidence is attached.
    """

    summary: str
    request: str | None = None
    response: str | None = None
    location: str | None = None


class Finding(BaseModel):
    """A single audit result."""

    id: str = ""
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    cwe: str | None = None
    owasp: str | None = None
    endpoint: str
    method: str = "GET"
    parameter: str | None = None
    detected_at: datetime = Field(default_factory=_utcnow)
    evidence: Evidence
    impact: str
    likelihood: str = "unknown"
    exploitation: str = "n/a"
    recommendation: str
    remediation_example: str | None = None
    references: list[str] = Field(default_factory=list)
    false_positive_hints: list[str] = Field(default_factory=list)
    state: FindingState = FindingState.OPEN

    def model_post_init(self, _context: object) -> None:
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        """Stable id used to correlate the same issue across scans."""

        basis = "|".join(
            [self.category, self.title, self.endpoint, self.method, self.parameter or ""]
        )
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
        return f"ISA-{digest}"


class Endpoint(BaseModel):
    """A discovered piece of attack surface."""

    url: str
    method: str = "GET"
    status: int | None = None
    content_type: str | None = None
    discovered_from: str | None = None
    title: str | None = None
    params: list[str] = Field(default_factory=list)

    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.url)


class DiscoveredForm(BaseModel):
    """An HTML form discovered during crawling.

    ``action`` is the resolved absolute submission URL; ``params`` are the input
    field names. Used to build injection points for safe parameter testing.
    """

    page_url: str
    action: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)

    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.action)


class Technology(BaseModel):
    """A detected technology/framework."""

    name: str
    version: str | None = None
    category: str = "unknown"
    evidence: str | None = None


class ScanStats(BaseModel):
    endpoints_discovered: int = 0
    forms_discovered: int = 0
    requests_made: int = 0
    findings_total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)


class ScopeInfo(BaseModel):
    """The authorised boundary of a scan, persisted for auditability."""

    target: str
    allowed_hosts: list[str] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """The complete, serialisable outcome of one audit run."""

    id: str
    target: str
    profile: str = "safe"
    scan_type: str = "web"
    authenticated: bool = False
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    scope: ScopeInfo
    technologies: list[Technology] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    isahat_version: str = ""

    def recompute_stats(self) -> None:
        by_sev: dict[str, int] = {}
        by_conf: dict[str, int] = {}
        for finding in self.findings:
            by_sev[finding.severity.value] = by_sev.get(finding.severity.value, 0) + 1
            by_conf[finding.confidence.value] = by_conf.get(finding.confidence.value, 0) + 1
        self.stats.endpoints_discovered = len(self.endpoints)
        self.stats.forms_discovered = len(self.forms)
        self.stats.findings_total = len(self.findings)
        self.stats.by_severity = by_sev
        self.stats.by_confidence = by_conf

    def findings_at_or_above(self, minimum: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity.rank >= minimum.rank]
