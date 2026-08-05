# ADR-0001: Monorepo with a single shared core engine

- **Status:** Accepted
- **Date:** 2026-08-05
- **Deciders:** IsaHat maintainers

## Context

IsaHat must run both as a terminal CLI and as a desktop GUI, and later expose a
web/API surface. The product requirement is explicit: **no important feature may
live in only one interface**, and other interfaces should be buildable later.

## Problem

How do we structure the codebase so that multiple front-ends share identical
audit behaviour, stay testable, and can evolve independently?

## Alternatives considered

- **Separate repos per app** — clear ownership, but high risk of behaviour
  drift, duplicated logic, and painful cross-cutting changes.
- **Single app with UI + logic entangled** — fast initially, but impossible to
  reuse the engine and hard to test headlessly.
- **Monorepo with a shared core (`isahat.core`) and thin front-ends** — one
  engine, many adapters.

## Decision

Adopt a **monorepo** with a single **shared core engine** in Python
(`isahat.core`). Front-ends (CLI now; desktop/web/API later) are thin adapters
that call the core. For the desktop app (Phase 3) we will use **Tauri + React**
for the shell and a **local FastAPI bridge** to the Python core, rather than
reimplementing logic in Rust/JS. Electron is only reconsidered if Tauri proves
insufficient.

## Consequences

- **Positive:** consistent behaviour across UIs; logic tested once, offline;
  a single place for detectors, scope and safety controls; easy to add front-ends.
- **Negative:** the desktop app pays the cost of bundling/bridging a Python
  runtime; monorepo tooling must handle multiple languages over time.

## Risks

- Python packaging for the desktop app can be fiddly → mitigate with a well-defined
  local API boundary and packaged runtime.
- Core could accumulate unrelated concerns → mitigate with clear package
  boundaries (see ARCHITECTURE.md) and code review.

## Reversibility

Moderately reversible. Because the boundary is an explicit in-process/local API,
a front-end could be split into its own repo consuming a published SDK without
rewriting engine logic.
