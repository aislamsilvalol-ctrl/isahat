"""Local persistence layer.

The MVP uses the standard-library ``sqlite3`` so IsaHat works fully offline with
zero external services. A future ADR covers moving to SQLAlchemy/PostgreSQL for
team deployments (see ``docs/adr/0003-storage.md``).
"""

from __future__ import annotations

from isahat.storage.database import ScanStore, default_db_path

__all__ = ["ScanStore", "default_db_path"]
