"""Stable, documented process exit codes for CI/pipeline use.

These are part of IsaHat's public contract; see ``docs/CLI.md``.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0  # scan completed; no gating threshold exceeded
    ERROR = 1  # unexpected runtime error
    USAGE = 2  # invalid usage, config, or scope
    THRESHOLD = 3  # findings met/exceeded --fail-on severity
    CANCELLED = 130  # interrupted by the user (SIGINT)
