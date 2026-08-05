"""Comparison between two scans of the same (or related) target.

Findings are correlated by their stable fingerprint id, so IsaHat can report
which issues are newly introduced, which were resolved, and which persist.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from isahat.core.models import Finding, ScanResult


@dataclass
class ScanDiff:
    base_id: str
    head_id: str
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return (
            f"{len(self.new)} new, {len(self.resolved)} resolved, "
            f"{len(self.unchanged)} unchanged"
        )


def compare_scans(base: ScanResult, head: ScanResult) -> ScanDiff:
    """Diff two results. ``base`` is the older/previous scan, ``head`` the newer."""

    base_index = {f.id: f for f in base.findings}
    head_index = {f.id: f for f in head.findings}

    new = [f for fid, f in head_index.items() if fid not in base_index]
    resolved = [f for fid, f in base_index.items() if fid not in head_index]
    unchanged = [f for fid, f in head_index.items() if fid in base_index]

    return ScanDiff(
        base_id=base.id,
        head_id=head.id,
        new=new,
        resolved=resolved,
        unchanged=unchanged,
    )


def diff_to_markdown(diff: ScanDiff) -> str:
    lines: list[str] = []
    add = lines.append
    add(f"# Scan comparison `{diff.base_id}` → `{diff.head_id}`")
    add("")
    add(f"**{diff.summary}.**")
    add("")

    def section(title: str, findings: list[Finding]) -> None:
        add(f"## {title} ({len(findings)})")
        add("")
        if not findings:
            add("_None._")
            add("")
            return
        for finding in findings:
            add(
                f"- `{finding.id}` **{finding.title}** "
                f"[{finding.severity.value} · {finding.confidence.value}] — "
                f"`{finding.method} {finding.endpoint}`"
            )
        add("")

    section("New findings", diff.new)
    section("Resolved findings", diff.resolved)
    section("Still present", diff.unchanged)
    return "\n".join(lines) + "\n"
