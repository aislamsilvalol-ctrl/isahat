"""Authentication material for authenticated scans.

An ``auth.json`` file lets IsaHat scan behind a login by attaching headers
and/or cookies to every request. Secrets here are never persisted in scan
results and are masked in any evidence (see :mod:`isahat.core.sanitize`).

Example ``auth.json``::

    {
      "headers": { "Authorization": "Bearer eyJhbGciOi..." },
      "cookies": { "session": "abc123" }
    }
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class AuthConfig(BaseModel):
    """Headers and cookies to attach to every request during a scan."""

    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)

    def is_empty(self) -> bool:
        return not self.headers and not self.cookies


def load_auth(path: str | Path) -> AuthConfig:
    """Load and validate an ``auth.json`` file.

    Raises ``FileNotFoundError`` if missing and ``ValueError`` if malformed, so
    the CLI can surface a clear error rather than scanning unauthenticated by
    surprise.
    """

    auth_path = Path(path)
    if not auth_path.is_file():
        raise FileNotFoundError(f"auth file not found: {auth_path}")
    try:
        raw = json.loads(auth_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"auth file is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("auth file root must be a JSON object")
    return AuthConfig.model_validate(raw)
