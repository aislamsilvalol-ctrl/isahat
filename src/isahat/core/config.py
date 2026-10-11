"""Loading and validation of ``isahat.yml`` configuration files.

The configuration mirrors the documented schema in ``docs/`` and README. Every
field has a safe default so a scan can run from CLI flags alone, without a
config file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class ProjectConfig(BaseModel):
    name: str = "isahat-project"


class TargetConfig(BaseModel):
    url: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)


class ScopeConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


# Labels accepted when a scan starts. The engine does not branch on them.
# Any other name would be stored as if a different mode had run.
IMPLEMENTED_PROFILE = "safe"
IMPLEMENTED_SCAN_TYPE = "web"


def unimplemented_scan_mode_reason(profile: str, scan_type: str) -> str | None:
    """Why this profile or scan type cannot start a scan, or ``None`` if it can.

    Resume does not use this. A checkpoint keeps the labels it was saved with.
    """

    if profile != IMPLEMENTED_PROFILE:
        return (
            f"Profile '{profile}' is not available yet. "
            f"Only '{IMPLEMENTED_PROFILE}' is implemented."
        )
    if scan_type != IMPLEMENTED_SCAN_TYPE:
        return (
            f"Scan type '{scan_type}' is not available yet. "
            "The engine always crawls the site and discovers APIs together."
        )
    return None


class ScanSettings(BaseModel):
    profile: str = "safe"
    concurrency: int = 5
    timeout: float = 10.0
    follow_redirects: bool = True
    max_pages: int = 100
    max_depth: int = 3

    @field_validator("concurrency")
    @classmethod
    def _positive_concurrency(cls, value: int) -> int:
        if value < 1:
            raise ValueError("concurrency must be >= 1")
        return value


class ReportSettings(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "markdown"])


class SafetySettings(BaseModel):
    destructive_tests: bool = False
    rate_limit: float = 3.0  # requests per second, per host
    require_scope_confirmation: bool = True
    # Opt-in controlled rate-limiting checks. Off by default: they issue a
    # small, paced burst of requests against authentication-looking endpoints.
    rate_limit_checks: bool = False
    rate_limit_burst: int = 10  # max requests per probed endpoint (hard cap 30)
    rate_limit_interval: float = 0.2  # seconds between burst requests


class ScanConfig(BaseModel):
    """Root configuration object."""

    project: ProjectConfig = Field(default_factory=ProjectConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    report: ReportSettings = Field(default_factory=ReportSettings)
    safety: SafetySettings = Field(default_factory=SafetySettings)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> ScanConfig:
        return cls.model_validate(data or {})


def load_config(path: str | Path | None) -> ScanConfig:
    """Load configuration from ``path`` or return safe defaults if ``None``.

    Raises ``FileNotFoundError`` when an explicit path is given but missing, so
    the CLI can surface a clear error instead of silently ignoring it.
    """

    if path is None:
        return ScanConfig()
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"config file not found: {config_path}")
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"config root must be a mapping, got {type(raw).__name__}")
    return ScanConfig.from_mapping(raw)


def find_default_config(start: Path | None = None) -> Path | None:
    """Look for an ``isahat.yml``/``isahat.yaml`` in ``start`` (cwd by default)."""

    base = start or Path.cwd()
    for name in ("isahat.yml", "isahat.yaml"):
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None
