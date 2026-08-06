# ADR-0004: GUI access to the engine via a loopback FastAPI bridge

- **Status:** Accepted
- **Date:** 2026-08-05
- **Deciders:** IsaHat maintainers

## Context

ADR-0001 established that every front-end is a thin adapter over the shared
Python core. Phase 3 adds the desktop app (Tauri + React + TypeScript), whose
UI is TypeScript running in a webview — it cannot call Python in-process. We
need a transport between the TypeScript shell and the engine that preserves the
shared-core guarantee: no re-implemented audit logic, no front-end-only
capabilities, no weakened safety controls.

## Problem

How does a TypeScript desktop shell drive the Python engine without duplicating
logic and without opening a network attack surface?

## Alternatives considered

- **Tauri commands into a Rust↔Python binding (PyO3 / sidecar stdio IPC)** —
  keeps everything in one process, but couples the release cycle of the shell
  to Python packaging, complicates code signing, and invents a second,
  GUI-only control plane that the CLI cannot share.
- **Embed the CLI as a child process and parse stdout** — zero new code, but
  fragile (presentation output is not a stable contract), poor for streaming
  progress, and makes review-state mutations awkward.
- **Loopback HTTP bridge (`isahat serve`, FastAPI) with SSE for progress** —
  a stable, testable, language-agnostic contract that any front-end (desktop,
  future web UI, third-party tools) can consume; FastAPI was already the
  stated stack for this purpose.

## Decision

Expose the engine through a FastAPI application (`isahat.api.create_app`)
served by uvicorn on `127.0.0.1` via `isahat serve`. The desktop webview calls
it with `fetch`/`EventSource`; CORS is restricted to localhost and Tauri
origins. Authorisation confirmation is a required field of the scan payload,
and scope enforcement, rate limiting and evidence sanitisation remain in the
core — so bypassing the UI gains an attacker nothing they could not already do
with the CLI on the same machine.

## Consequences

- The bridge is fully covered by offline tests (`TestClient` + the bundled lab
  app), including a whole scan driven through HTTP.
- `ScanStore` became thread-safe (bridge jobs finish on worker threads).
- Any future front-end gets a stable contract for free; the CLI and GUI cannot
  drift because both go through the same engine and storage.
- Binding beyond loopback prints an explicit warning but remains possible for
  trusted setups (documented risk).

## Risks

- A malicious local process could drive the API while it runs. Mitigation:
  loopback-only default, no destructive capabilities exist in the engine at
  all, and scans require the same explicit confirmation as the CLI prompt.
- SSE/HTTP adds moving parts versus stdio IPC. Mitigation: the event stream is
  an addition, not a requirement — polling `/scans/{id}/status` suffices.

## Reversibility

The bridge is additive: removing it deletes `isahat.api` and `apps/desktop`
without touching the engine, storage or CLI. The in-process Python API remains
the primary contract (docs/API.md).
