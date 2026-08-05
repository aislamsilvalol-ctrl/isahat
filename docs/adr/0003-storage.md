# ADR-0003: Local storage — SQLite (stdlib) first

- **Status:** Accepted
- **Date:** 2026-08-05
- **Deciders:** IsaHat maintainers

## Context

IsaHat must persist scans locally to support history, `report`, `compare` and
`list`. The stated stack mentions SQLAlchemy/Alembic and optional PostgreSQL for
teams. Phase 1 is a single-user, offline-first tool.

## Problem

What persistence approach gives us a robust, offline, zero-config store now,
without over-engineering for a multi-user server we do not yet have?

## Alternatives considered

- **SQLAlchemy + Alembic + SQLite/PostgreSQL now** — matches the long-term
  vision, but adds heavy dependencies and migration machinery before we have the
  schema churn or multi-user needs that justify them.
- **Flat JSON files** — trivial, but poor for listing/filtering/comparison at
  scale and prone to concurrent-write issues.
- **Python stdlib `sqlite3` with a thin repository** — no extra dependencies,
  fully offline, fast enough, and the schema is simple (indexed columns + a JSON
  payload).

## Decision

Use the standard-library **`sqlite3`** with a small `ScanStore` repository. Each
scan is stored as indexed summary columns plus the full `ScanResult` JSON
payload, so listing/comparison are fast and the complete result is always
recoverable.

## Consequences

- **Positive:** zero external dependencies; works offline; simple to reason
  about and test; easy backup (a single file under `~/.isahat`).
- **Negative:** not suited to concurrent multi-user servers; no rich query layer
  or migrations yet.

## Risks

- Schema evolution is manual for now → mitigate by storing the full JSON payload
  (forward-compatible) and keeping indexed columns minimal.
- Shared-host privacy → documented in THREAT-MODEL.md (T10).

## Reversibility

Highly reversible. The `ScanStore` interface hides SQLite behind a small API. A
future ADR can introduce SQLAlchemy + Alembic and PostgreSQL for team/server
deployments by implementing the same interface, and a one-off importer can copy
existing scans from the JSON payloads.
