"""Allow ``python -m isahat`` to behave exactly like the ``isahat`` script."""

from __future__ import annotations

from isahat.cli.main import app

if __name__ == "__main__":  # pragma: no cover - trivial entrypoint
    app()
