"""SQLite-backed storage for scan results and their history.

Each scan is stored as an indexed row plus a full JSON payload, so listing and
comparison are fast while the complete result is always recoverable.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from isahat.core.models import ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    profile       TEXT NOT NULL,
    scan_type     TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    findings_total INTEGER NOT NULL DEFAULT 0,
    critical      INTEGER NOT NULL DEFAULT 0,
    high          INTEGER NOT NULL DEFAULT 0,
    medium        INTEGER NOT NULL DEFAULT 0,
    low           INTEGER NOT NULL DEFAULT 0,
    info          INTEGER NOT NULL DEFAULT 0,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
"""


def default_db_path() -> Path:
    """Return the default database location, respecting ``ISAHAT_HOME``."""

    home = os.environ.get("ISAHAT_HOME")
    base = Path(home) if home else Path.home() / ".isahat"
    base.mkdir(parents=True, exist_ok=True)
    return base / "isahat.db"


@dataclass
class ScanSummary:
    id: str
    target: str
    profile: str
    started_at: str
    finished_at: str | None
    findings_total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ScanStore:
    """A thin repository over a SQLite database of scans."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_db_path()
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ScanStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def save(self, result: ScanResult) -> None:
        by_sev = result.stats.by_severity
        self._conn.execute(
            """
            INSERT INTO scans (
                id, target, profile, scan_type, started_at, finished_at,
                findings_total, critical, high, medium, low, info, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                target=excluded.target,
                profile=excluded.profile,
                scan_type=excluded.scan_type,
                started_at=excluded.started_at,
                finished_at=excluded.finished_at,
                findings_total=excluded.findings_total,
                critical=excluded.critical,
                high=excluded.high,
                medium=excluded.medium,
                low=excluded.low,
                info=excluded.info,
                payload=excluded.payload
            """,
            (
                result.id,
                result.target,
                result.profile,
                result.scan_type,
                result.started_at.isoformat(),
                result.finished_at.isoformat() if result.finished_at else None,
                result.stats.findings_total,
                by_sev.get("critical", 0),
                by_sev.get("high", 0),
                by_sev.get("medium", 0),
                by_sev.get("low", 0),
                by_sev.get("info", 0),
                result.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get(self, scan_id: str) -> ScanResult | None:
        row = self._conn.execute(
            "SELECT payload FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        return ScanResult.model_validate(json.loads(row["payload"]))

    def get_latest_for_target(self, target: str) -> ScanResult | None:
        row = self._conn.execute(
            "SELECT payload FROM scans WHERE target = ? ORDER BY started_at DESC LIMIT 1",
            (target,),
        ).fetchone()
        if row is None:
            return None
        return ScanResult.model_validate(json.loads(row["payload"]))

    def list(self, limit: int = 50) -> list[ScanSummary]:
        rows = self._conn.execute(
            """
            SELECT id, target, profile, started_at, finished_at,
                   findings_total, critical, high, medium, low, info
            FROM scans ORDER BY started_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            ScanSummary(
                id=row["id"],
                target=row["target"],
                profile=row["profile"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                findings_total=row["findings_total"],
                critical=row["critical"],
                high=row["high"],
                medium=row["medium"],
                low=row["low"],
                info=row["info"],
            )
            for row in rows
        ]

    def delete(self, scan_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self._conn.commit()
        return cur.rowcount > 0
