"""SQLite-backed storage for scan results and their history.

Each scan is stored as an indexed row plus a full JSON payload, so listing and
comparison are fast while the complete result is always recoverable.
"""

from __future__ import annotations

import builtins
import functools
import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from isahat.core.models import FindingAnnotation, FindingState, ScanResult
from isahat.core.state import ScanCheckpoint

_F = TypeVar("_F", bound=Callable[..., Any])


def _synchronized(method: _F) -> _F:
    """Serialise a ScanStore method on the instance lock."""

    @functools.wraps(method)
    def wrapper(self: ScanStore, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]

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
CREATE TABLE IF NOT EXISTS checkpoints (
    scan_id   TEXT PRIMARY KEY,
    target    TEXT NOT NULL,
    stage     TEXT NOT NULL,
    payload   TEXT NOT NULL,
    saved_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS annotations (
    finding_id TEXT PRIMARY KEY,
    state      TEXT NOT NULL,
    comment    TEXT,
    updated_at TEXT NOT NULL
);
"""


def default_db_path() -> Path:
    """Return the default database location, respecting ``ISAHAT_HOME``."""

    home = os.environ.get("ISAHAT_HOME")
    base = Path(home) if home else Path.home() / ".isahat"
    base.mkdir(parents=True, exist_ok=True)
    return base / "isahat.db"


@dataclass
class CheckpointSummary:
    """An interrupted scan that can be resumed, for listing purposes."""

    scan_id: str
    target: str
    stage: str
    saved_at: str


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
    """A thin repository over a SQLite database of scans.

    The connection is opened with ``check_same_thread=False`` so the bridge API
    (whose scan jobs finish on asyncio worker threads) can share one store; a
    re-entrant lock serialises access, which is fine at local-app scale.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        import threading

        self.path = Path(path) if path is not None else default_db_path()
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    @_synchronized
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ScanStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _upsert_scan(self, result: ScanResult) -> None:
        """Insert or update a scan row. Caller holds the lock and commits."""

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

    @_synchronized
    def save(self, result: ScanResult) -> None:
        self._upsert_scan(result)
        self._conn.commit()

    @_synchronized
    def finalize_scan(self, result: ScanResult) -> None:
        """Persist a finished scan and drop its checkpoint in one transaction.

        A crash before ``commit`` rolls both statements back, so the caller
        still has either the stored result or the checkpoint to resume from.
        """

        try:
            self._upsert_scan(result)
            self._conn.execute(
                "DELETE FROM checkpoints WHERE scan_id = ?",
                (result.id,),
            )
            self._conn.commit()
        except Exception:  # noqa: BLE001 - any failure must undo both statements
            self._conn.rollback()
            raise

    @_synchronized
    def get(self, scan_id: str) -> ScanResult | None:
        row = self._conn.execute(
            "SELECT payload FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        return ScanResult.model_validate(json.loads(row["payload"]))

    @_synchronized
    def get_latest_for_target(self, target: str) -> ScanResult | None:
        row = self._conn.execute(
            "SELECT payload FROM scans WHERE target = ? ORDER BY started_at DESC LIMIT 1",
            (target,),
        ).fetchone()
        if row is None:
            return None
        return ScanResult.model_validate(json.loads(row["payload"]))

    @_synchronized
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

    @_synchronized
    def delete(self, scan_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self._conn.commit()
        return cur.rowcount > 0

    # -- checkpoints (scan resume) -----------------------------------------

    @_synchronized
    def save_checkpoint(self, checkpoint: ScanCheckpoint) -> None:
        self._conn.execute(
            """
            INSERT INTO checkpoints (scan_id, target, stage, payload, saved_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                target=excluded.target,
                stage=excluded.stage,
                payload=excluded.payload,
                saved_at=excluded.saved_at
            """,
            (
                checkpoint.scan_id,
                checkpoint.target,
                checkpoint.stage,
                checkpoint.model_dump_json(),
                datetime.now(UTC).isoformat(),
            ),
        )
        self._conn.commit()

    @_synchronized
    def load_checkpoint(self, scan_id: str) -> ScanCheckpoint | None:
        row = self._conn.execute(
            "SELECT payload FROM checkpoints WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        return ScanCheckpoint.model_validate(json.loads(row["payload"]))

    @_synchronized
    def delete_checkpoint(self, scan_id: str) -> None:
        self._conn.execute("DELETE FROM checkpoints WHERE scan_id = ?", (scan_id,))
        self._conn.commit()

    @_synchronized
    def list_checkpoints(self) -> builtins.list[CheckpointSummary]:
        rows = self._conn.execute(
            """
            SELECT scan_id, target, stage, saved_at
            FROM checkpoints ORDER BY saved_at DESC
            """
        ).fetchall()
        return [
            CheckpointSummary(
                scan_id=row["scan_id"],
                target=row["target"],
                stage=row["stage"],
                saved_at=row["saved_at"],
            )
            for row in rows
        ]

    # -- annotations (finding review state) ---------------------------------

    @_synchronized
    def set_annotation(self, annotation: FindingAnnotation) -> None:
        self._conn.execute(
            """
            INSERT INTO annotations (finding_id, state, comment, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                state=excluded.state,
                comment=excluded.comment,
                updated_at=excluded.updated_at
            """,
            (
                annotation.finding_id,
                annotation.state.value,
                annotation.comment,
                annotation.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    @_synchronized
    def get_annotations(self) -> dict[str, FindingAnnotation]:
        rows = self._conn.execute(
            "SELECT finding_id, state, comment, updated_at FROM annotations"
        ).fetchall()
        return {
            row["finding_id"]: FindingAnnotation(
                finding_id=row["finding_id"],
                state=FindingState(row["state"]),
                comment=row["comment"],
                updated_at=datetime.fromisoformat(row["updated_at"]),
            )
            for row in rows
        }

    @_synchronized
    def apply_annotations(self, result: ScanResult) -> ScanResult:
        """Overlay stored review state onto a scan's findings."""

        annotations = self.get_annotations()
        for finding in result.findings:
            annotation = annotations.get(finding.id)
            if annotation is not None:
                finding.state = annotation.state
        return result
