# IsaHat Desktop (Phase 3 — planned)

The desktop application is a **thin front-end** over the shared core engine, not
a reimplementation. See [ADR-0001](../../docs/adr/0001-monorepo-and-shared-core.md).

## Planned stack

- **Tauri + React + TypeScript** for the shell (small binaries, no Chromium
  bundle like Electron).
- A **local FastAPI bridge** exposing the Python core over `127.0.0.1`, mirroring
  the in-process API in [docs/API.md](../../docs/API.md) 1:1.

## Planned capabilities

Create projects · register authorised targets · define scope · import auth ·
choose profile · start/stop scans · live findings · filter by severity · view
evidence and requests/responses · generate reports · compare scans · mark
false-positive / fixed · comments · export · manage plugins · configure
integrations · history and trend view.

## Design direction

Modern, professional, minimal — think Linear/Vercel/Raycast in polish, with an
original IsaHat identity. Explicitly avoid the "hacker terminal", neon, and
cluttered-legacy-dashboard looks. A serious security-engineering product.

> This directory is a placeholder until Phase 3 begins. The engine it will use
> already lives in `src/isahat/core` and is fully usable today from the CLI.
