"""Built-in detectors and the registry used by the engine.

Detectors are the units of analysis. In the MVP they are registered here; the
plugin system (Phase 5) will let external packages contribute more via the same
:class:`~isahat.core.detectors.base.Detector` contract.
"""

from __future__ import annotations

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.detectors.cookies import CookieSecurityDetector
from isahat.core.detectors.security_headers import SecurityHeadersDetector
from isahat.core.detectors.sensitive_files import SensitiveFilesDetector

__all__ = [
    "CookieSecurityDetector",
    "Detector",
    "DetectorContext",
    "SecurityHeadersDetector",
    "SensitiveFilesDetector",
    "default_detectors",
]


def default_detectors() -> list[Detector]:
    """Return the built-in detectors enabled by default in the safe profile."""

    return [
        SecurityHeadersDetector(),
        CookieSecurityDetector(),
        SensitiveFilesDetector(),
    ]
