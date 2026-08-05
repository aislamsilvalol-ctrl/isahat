"""CSV reporter — a flat, spreadsheet-friendly view of findings."""

from __future__ import annotations

import csv
import io

from isahat.core.models import ScanResult
from isahat.core.risk import priority_score

_COLUMNS = [
    "id",
    "title",
    "category",
    "severity",
    "confidence",
    "priority",
    "cwe",
    "owasp",
    "method",
    "endpoint",
    "parameter",
    "state",
    "recommendation",
]


def to_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_COLUMNS)
    for finding in result.findings:
        writer.writerow(
            [
                finding.id,
                finding.title,
                finding.category,
                finding.severity.value,
                finding.confidence.value,
                priority_score(finding),
                finding.cwe or "",
                finding.owasp or "",
                finding.method,
                finding.endpoint,
                finding.parameter or "",
                finding.state.value,
                finding.recommendation,
            ]
        )
    return buffer.getvalue()
