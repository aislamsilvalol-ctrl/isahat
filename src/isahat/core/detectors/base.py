"""The Detector contract shared by built-in detectors and plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from isahat.core.http import HttpResponse, SafeHttpClient
from isahat.core.injection import InjectionPoint
from isahat.core.models import DiscoveredForm, Finding
from isahat.core.scope import Scope


@dataclass
class DetectorContext:
    """Everything a detector may need, passed in explicitly (no globals).

    ``responses`` holds traffic already captured by the crawler so passive
    detectors never issue new requests. Active detectors may use ``client`` to
    make additional *scoped, non-destructive* requests, or iterate the
    pre-computed ``injection_points`` for safe parameter testing.
    """

    target: str
    scope: Scope
    client: SafeHttpClient
    responses: list[HttpResponse]
    forms: list[DiscoveredForm] = field(default_factory=list)
    injection_points: list[InjectionPoint] = field(default_factory=list)
    destructive: bool = False


class Detector(ABC):
    """Base class for all detectors.

    Subclasses declare a stable ``name`` and human ``category`` and implement
    :meth:`run`, returning zero or more findings. Detectors must never raise on
    ordinary target behaviour; unexpected errors are isolated by the engine.
    """

    name: str = "detector"
    category: str = "generic"

    @abstractmethod
    async def run(self, ctx: DetectorContext) -> list[Finding]:
        """Analyse the context and return findings (possibly empty)."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r}>"
