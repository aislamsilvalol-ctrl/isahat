# Architecture

IsaHat is built around a single **audit engine**. Every front-end — the CLI
today, the desktop app and web/API later — is a thin adapter over that engine.
No important capability lives in a front-end.

## Layers

```
┌──────────────────────────────────────────────────────────────┐
│ Front-ends (thin)                                              │
│   apps/cli (Typer)  ·  apps/desktop (Tauri, Phase 3)  ·  api   │
└───────────────┬────────────────────────────────────────────—─┘
                │ in-process calls (same language) / local API
┌───────────────▼────────────────────────────────────────────—─┐
│ core engine (isahat.core)                                      │
│   config → scope → http → crawler → tech → detectors → risk    │
└───────┬───────────────────────────────┬───────────────────────┘
        │                               │
┌───────▼────────┐              ┌────────▼─────────┐
│ storage        │              │ reporting        │
│ (SQLite)       │              │ (json/md/diff)   │
└────────────────┘              └──────────────────┘
```

## Package map

| Package | Responsibility |
| --- | --- |
| `isahat.core.config` | Load/validate `isahat.yml`; safe defaults |
| `isahat.core.scope` | Deny-by-default authorisation boundary |
| `isahat.core.http` | Rate-limited, scope-checked, non-destructive client |
| `isahat.core.crawler` | Breadth-first, scope-bound surface discovery |
| `isahat.core.tech` | Passive technology fingerprinting |
| `isahat.core.detectors` | Units of analysis (`Detector` contract) |
| `isahat.core.risk` | Severity × confidence → priority |
| `isahat.core.sanitize` | Secret masking (privacy guarantee) |
| `isahat.core.engine` | Orchestrates the pipeline into a `ScanResult` |
| `isahat.core.models` | Serialisable data contracts (the internal API) |
| `isahat.storage` | Local SQLite persistence + history |
| `isahat.reporting` | JSON / Markdown / comparison output |
| `isahat.cli` | Presentation + orchestration only |

## The scan pipeline

1. **Resolve config** (`isahat.yml` + CLI overrides), producing a `ScanConfig`.
2. **Build scope** from the target and allowed hosts. Deny-by-default.
3. **Confirm authorisation** (interactive prompt or `--yes`).
4. **Crawl** within scope, capturing responses and building an endpoint list.
5. **Fingerprint** technologies passively from captured responses.
6. **Run detectors**, each producing `Finding`s (severity + confidence).
7. **Prioritise** findings and **assemble** a `ScanResult`.
8. **Persist** to SQLite and **render** reports.

## Data contracts

The stable internal API is the set of Pydantic models in
`isahat.core.models`: `ScanResult`, `Finding`, `Endpoint`, `Technology`, plus
the `Severity`, `Confidence` and `FindingState` enums. Because they are
serialisable, a scan can be stored, reloaded, compared and rendered without
loss — and future front-ends can consume the exact same structures.

## Why a shared core?

- **Consistency:** the CLI and GUI cannot drift in behaviour.
- **Testability:** logic is tested once, offline, without a UI.
- **Extensibility:** new front-ends and plugins target one contract.

See the ADRs in [`adr/`](adr/) for the reasoning behind these choices, including
the language/runtime split for the desktop app (ADR-0001) and storage (ADR-0003).

## Concurrency & safety model

- Async I/O (`httpx` + `asyncio`) with a bounded semaphore for concurrency.
- A per-host rate limiter spaces requests.
- Detector failures are isolated: one failing detector never aborts a scan.
- The crawler caps pages and depth to bound resource use.
