# IsaHat Desktop

A **thin shell** over the shared core engine — no audit logic is reimplemented
here. The UI talks to the local bridge (`isahat serve`) over loopback HTTP, so
every capability available in the app is exactly the CLI's capability. See
[ADR-0001](../../docs/adr/0001-monorepo-and-shared-core.md).

## Architecture

```
┌─────────────────────────────────────────────┐
│ Tauri webview (React + TypeScript)          │
│   screens: dashboard · new audit · scan     │
│            detail · compare                 │
└──────────────┬──────────────────────────────┘
               │ HTTP / SSE, 127.0.0.1:8741 (CORS: localhost only)
┌──────────────▼──────────────────────────────┐
│ isahat serve  (FastAPI bridge)              │
│   POST /scans · GET /scans · /scans/{id}    │
│   /scans/{id}/events (SSE) · /report        │
│   /findings/{id}/annotation · /compare      │
└──────────────┬──────────────────────────────┘
               │ in-process
┌──────────────▼──────────────────────────────┐
│ isahat.core — engine, crawler, detectors,   │
│ scope guard, sanitiser (same as the CLI)    │
└─────────────────────────────────────────────┘
```

Safety properties are enforced server-side, so the UI cannot bypass them: the
bridge rejects scans without an explicit `confirmed: true`, the scope guard and
rate limits live in the core, and secrets are masked before leaving the engine.
The bridge also requires a local bearer token (`bridge.token`, mode 0600). The
UI does not ship a token: in development the Vite proxy reads the file and
attaches the header; a packaged Tauri build asks the shell to read the same
file. `GET /health` stays unauthenticated so the offline banner still works.

## Running (development)

Requires: Python env with IsaHat installed (`pip install -e .`), Node.js ≥ 18,
and Rust (only for the Tauri bundle — the browser dev flow works without it).

```bash
# 1. start the local engine bridge
isahat serve                      # listens on 127.0.0.1:8741

# 2. in another terminal, start the UI (proxies /api → 8741)
cd apps/desktop
npm install
npm run dev                       # http://localhost:1420

# 3. optional: native window instead of the browser
npm run tauri dev                 # needs Rust toolchain
```

## What the app does today

- Dashboard with per-severity totals and live scan history (auto-refresh).
- New audit form with target/profile/type/auth import and the same
  authorisation checklist the CLI enforces (the bridge rejects unconfirmed
  scans regardless of the UI).
- Live audit view: progress events streamed over SSE, findings as they are
  saved, severity filters, sanitized evidence (request/response), detected
  stack, and report export (HTML/Markdown/JSON).
- Review workflow: mark findings fixed / false-positive / accepted-risk /
  reopen — persisted in SQLite by finding fingerprint, so decisions survive
  re-scans of the same endpoint.
- Compare two audits of a target (new / resolved / unchanged).

## Verification status

The bridge layer is covered by automated tests (`tests/unit/test_api_bridge.py`,
including a full scan through the API against the bundled lab app). The React
UI is hand-written to strict TypeScript (`npm run typecheck`); UI-level
interaction tests (Playwright/Vitest) are planned for Phase 5 alongside
end-to-end desktop packaging in CI.

## Design direction

Modern, professional, minimal — Linear/Vercel/Raycast levels of polish with an
original IsaHat identity. No "hacker terminal" aesthetic, no neon, no cluttered
legacy dashboards.
