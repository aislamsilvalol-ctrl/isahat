"""IsaHat core engine — the single audit engine shared by every front-end.

Importing :mod:`isahat.core` gives access to the stable, in-process API that the
CLI (and later the desktop/web/API apps) build upon. Nothing important should
live only in a front-end: it belongs here.
"""

from __future__ import annotations

from isahat.core.auth import AuthConfig, load_auth
from isahat.core.config import ScanConfig, load_config
from isahat.core.engine import ScanEngine
from isahat.core.models import (
    Confidence,
    DiscoveredForm,
    Endpoint,
    Evidence,
    Finding,
    FindingState,
    ScanResult,
    Severity,
    Technology,
)
from isahat.core.scope import Scope, ScopeViolation

__all__ = [
    "AuthConfig",
    "Confidence",
    "DiscoveredForm",
    "Endpoint",
    "Evidence",
    "Finding",
    "FindingState",
    "ScanConfig",
    "ScanEngine",
    "ScanResult",
    "Scope",
    "ScopeViolation",
    "Severity",
    "Technology",
    "load_auth",
    "load_config",
]
