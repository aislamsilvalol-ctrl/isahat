"""Scope policy — the safety boundary that keeps IsaHat inside authorisation.

Every URL the engine is about to touch is checked here first. If a URL is not
explicitly in scope, it is rejected. This is deliberately conservative: the
default answer is "no".
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from urllib.parse import urlparse

from isahat.core.config import ScanConfig
from isahat.core.models import ScopeInfo


class ScopeViolation(Exception):
    """Raised when an operation would step outside the authorised scope."""


@dataclass
class Scope:
    """Immutable-ish description of what is authorised for a scan.

    Hosts are matched case-insensitively. Path globs use shell-style matching
    (``fnmatch``). If ``include`` is empty, all paths on allowed hosts are in
    scope except those matched by ``exclude`` (exclude always wins).
    """

    target: str
    allowed_hosts: set[str]
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, target: str, config: ScanConfig) -> Scope:
        hosts: set[str] = set()
        target_host = urlparse(target).hostname
        if target_host:
            hosts.add(target_host.lower())
        for host in config.target.allowed_hosts:
            cleaned = host.strip().lower()
            if cleaned:
                hosts.add(cleaned)
        if not hosts:
            raise ScopeViolation(
                "cannot derive an allowed host from the target; provide a full URL"
            )
        return cls(
            target=target,
            allowed_hosts=hosts,
            include=list(config.scope.include),
            exclude=list(config.scope.exclude),
        )

    def host_allowed(self, host: str | None) -> bool:
        if not host:
            return False
        return host.lower() in self.allowed_hosts

    def path_allowed(self, path: str) -> bool:
        normalised = path or "/"
        for pattern in self.exclude:
            if fnmatch.fnmatch(normalised, pattern):
                return False
        if not self.include:
            return True
        return any(fnmatch.fnmatch(normalised, pattern) for pattern in self.include)

    def allows(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not self.host_allowed(parsed.hostname):
            return False
        return self.path_allowed(parsed.path or "/")

    def require(self, url: str) -> None:
        """Assert ``url`` is in scope or raise :class:`ScopeViolation`."""

        if not self.allows(url):
            raise ScopeViolation(f"url outside authorised scope: {url}")

    def to_info(self) -> ScopeInfo:
        return ScopeInfo(
            target=self.target,
            allowed_hosts=sorted(self.allowed_hosts),
            include=list(self.include),
            exclude=list(self.exclude),
        )

    def describe(self) -> str:
        hosts = ", ".join(sorted(self.allowed_hosts))
        include = ", ".join(self.include) if self.include else "(all paths)"
        exclude = ", ".join(self.exclude) if self.exclude else "(none)"
        return f"hosts: {hosts}\ninclude: {include}\nexclude: {exclude}"
