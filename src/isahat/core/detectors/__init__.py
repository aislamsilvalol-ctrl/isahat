"""Built-in detectors and the registry used by the engine.

Detectors are the units of analysis. In the MVP they are registered here; the
plugin system (Phase 5) will let external packages contribute more via the same
:class:`~isahat.core.detectors.base.Detector` contract.
"""

from __future__ import annotations

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.detectors.cookies import CookieSecurityDetector
from isahat.core.detectors.cors import CorsDetector
from isahat.core.detectors.open_redirect import OpenRedirectDetector
from isahat.core.detectors.path_traversal import PathTraversalDetector
from isahat.core.detectors.reflected_xss import ReflectedXssDetector
from isahat.core.detectors.security_headers import SecurityHeadersDetector
from isahat.core.detectors.sensitive_files import SensitiveFilesDetector
from isahat.core.detectors.sqli_error import SqlInjectionErrorDetector

__all__ = [
    "CookieSecurityDetector",
    "CorsDetector",
    "Detector",
    "DetectorContext",
    "OpenRedirectDetector",
    "PathTraversalDetector",
    "ReflectedXssDetector",
    "SecurityHeadersDetector",
    "SensitiveFilesDetector",
    "SqlInjectionErrorDetector",
    "default_detectors",
]


def default_detectors() -> list[Detector]:
    """Return the built-in detectors enabled by default in the safe profile.

    All of these use only non-destructive requests (passive analysis or
    scoped, capped GET probes with benign markers).
    """

    return [
        SecurityHeadersDetector(),
        CookieSecurityDetector(),
        SensitiveFilesDetector(),
        CorsDetector(),
        OpenRedirectDetector(),
        ReflectedXssDetector(),
        SqlInjectionErrorDetector(),
        PathTraversalDetector(),
    ]
