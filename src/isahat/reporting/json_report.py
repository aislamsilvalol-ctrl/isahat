"""JSON reporter — a faithful, machine-readable dump of the scan result."""

from __future__ import annotations

from isahat.core.models import ScanResult


def to_json(result: ScanResult) -> str:
    """Serialise the full result as pretty-printed JSON."""

    return result.model_dump_json(indent=2)
