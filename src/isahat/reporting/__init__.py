"""Report generation from a :class:`~isahat.core.models.ScanResult`.

Reporters are pure functions from a result to text, so they are trivial to test
and identical across every front-end. Evidence is already sanitised upstream at
detection time; reporters never see raw secrets.
"""

from __future__ import annotations

from isahat.reporting.compare import ScanDiff, compare_scans, diff_to_markdown
from isahat.reporting.json_report import to_json
from isahat.reporting.markdown_report import to_markdown

__all__ = [
    "ScanDiff",
    "compare_scans",
    "diff_to_markdown",
    "render",
    "to_json",
    "to_markdown",
]

_RENDERERS = {
    "json": to_json,
    "markdown": to_markdown,
    "md": to_markdown,
}


def render(result, fmt: str) -> str:  # type: ignore[no-untyped-def]
    """Render ``result`` in the named format. Raises ``ValueError`` if unknown."""

    key = fmt.lower()
    if key not in _RENDERERS:
        raise ValueError(f"unsupported report format: {fmt}")
    return _RENDERERS[key](result)


def extension_for(fmt: str) -> str:
    return {"json": "json", "markdown": "md", "md": "md"}.get(fmt.lower(), fmt.lower())
