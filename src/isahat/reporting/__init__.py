"""Report generation from a :class:`~isahat.core.models.ScanResult`.

Reporters are pure functions from a result to text, so they are trivial to test
and identical across every front-end. Evidence is already sanitised upstream at
detection time; reporters never see raw secrets.
"""

from __future__ import annotations

from isahat.reporting.compare import ScanDiff, compare_scans, diff_to_markdown
from isahat.reporting.csv_report import to_csv
from isahat.reporting.json_report import to_json
from isahat.reporting.markdown_report import to_markdown
from isahat.reporting.sarif_report import to_sarif

__all__ = [
    "ScanDiff",
    "compare_scans",
    "diff_to_markdown",
    "extension_for",
    "render",
    "to_csv",
    "to_json",
    "to_markdown",
    "to_sarif",
]

_RENDERERS = {
    "json": to_json,
    "markdown": to_markdown,
    "md": to_markdown,
    "sarif": to_sarif,
    "csv": to_csv,
}


def render(result, fmt: str) -> str:  # type: ignore[no-untyped-def]
    """Render ``result`` in the named format. Raises ``ValueError`` if unknown."""

    key = fmt.lower()
    if key not in _RENDERERS:
        raise ValueError(f"unsupported report format: {fmt}")
    return _RENDERERS[key](result)


def extension_for(fmt: str) -> str:
    return {"json": "json", "markdown": "md", "md": "md", "sarif": "sarif", "csv": "csv"}.get(
        fmt.lower(), fmt.lower()
    )
