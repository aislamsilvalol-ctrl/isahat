"""Local HTTP bridge over the shared core engine.

The desktop app (and any future front-end) talks to this FastAPI application
instead of re-implementing audit logic — the CLI and the GUI share exactly the
same engine, storage and reporters through it.
"""

from __future__ import annotations

from isahat.api.app import create_app
from isahat.api.token import BridgeTokenError, bridge_token_path

__all__ = ["BridgeTokenError", "bridge_token_path", "create_app"]
