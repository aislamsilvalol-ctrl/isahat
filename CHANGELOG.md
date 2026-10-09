# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Resuming a scan restores the profile, scan type and rate-limit flag saved in
  the checkpoint. A checkpoint without that contract is refused. Authenticated
  scans are refused too: there is no secure credential store, so headers and
  cookies are not written into the checkpoint.
- The local bridge requires a bearer token. The first `isahat serve` writes
  `bridge.token` (mode 0600) next to the SQLite database and reuses it. A file
  that group or other users can access is refused instead of being chmod'd,
  because the secret may already have been read. `GET /health` stays open.
  `isahat bridge token --path` prints the file path and never the token value.
  The desktop reads that file itself (Vite dev proxy, or the Tauri shell in a
  packaged build) and does not embed the token.
- A finished scan saves its result and removes the checkpoint in one SQLite
  transaction. A detector that raises is not marked complete, so resume runs
  it again.
- Checkpoints redact `Authorization`, `Cookie`, `Set-Cookie` secrets,
  `Proxy-Authorization` and API-key style headers. Response bodies are stored
  as a hash, a size and a masked capped copy, which is what resume reads.
- Redirects are followed manually. Each hop is checked against the scope, and
  an out-of-scope `Location` is not requested.

### Added

- **Local bridge API** (`isahat serve`, `isahat.api`): a loopback-only FastAPI
  application exposing the shared engine to front-ends — start scans
  (`POST /scans`, explicit authorisation confirmation required), live progress
  over SSE (`/scans/{id}/events`), status, history, rendered reports
  (`/scans/{id}/report?fmt=`), comparison (`/compare`) and health. CORS is
  restricted to localhost/Tauri origins; scope enforcement and evidence
  sanitisation stay in the core, so no client can bypass them.
- **Finding review workflow** (`FindingAnnotation`, SQLite `annotations`
  table): mark findings fixed / false-positive / accepted-risk / reopen, with
  comments, keyed by the stable finding fingerprint so review decisions survive
  re-scans of the same endpoint. `ScanStore` is now thread-safe
  (`check_same_thread=False` + a re-entrant lock) so bridge scan jobs can share
  it across asyncio worker threads.
- **Desktop application** (`apps/desktop`): Tauri 2 + React 18 + TypeScript
  shell over the bridge — dashboard with per-severity totals and live history,
  new-audit form with the authorisation checklist (server-enforced), live audit
  view with SSE progress, findings with severity filters and sanitized evidence
  viewer, report export (HTML/Markdown/JSON), review actions and audit
  comparison. Strict TypeScript, `npm run typecheck` in CI (Node 20 job).
- CI: `desktop` job type-checks and builds the UI bundle on every PR.

### Phase 2 additions

- **Form and parameter discovery** during crawling (`DiscoveredForm`,
  `Endpoint.params`), preserving query parameters across redirects.
- **Injection-point model** (`isahat.core.injection`): safe, GET-only,
  de-duplicated and capped points for parameter testing.
- New **safe active detectors** (all non-destructive, scoped, capped):
  - CORS misconfiguration (controlled `Origin` probe)
  - Open redirect (non-following `Location` probe)
  - Reflected XSS (benign marker; unencoded-reflection check)
  - Error-based SQL injection (single-quote probe; confidence capped at probable)
  - Path traversal / LFI (read-only traversal payloads matched against
    system-file signatures such as `/etc/passwd`)
- **Authenticated scans** via `--auth auth.json` (`isahat.core.auth`): headers
  and cookies are attached to every request; secrets are never persisted and are
  masked in evidence. Results record only an `authenticated` flag.
- **API surface discovery** (`isahat.core.api`): probes conventional
  OpenAPI/Swagger locations and GraphQL endpoints (read-only GET introspection
  probe), producing an operation inventory per discovered API (`ApiSpec`).
- New **API-security detectors**:
  - GraphQL introspection enabled (confirmed from the discovery probe)
  - Excessive data exposure in JSON responses (sensitive-looking fields such as
    `password_hash`; values masked in evidence; confidence capped at probable)
- **SARIF 2.1.0**, **CSV** and self-contained **HTML** reporters
  (`isahat report --format sarif|csv|html`). The HTML report is script-free and
  escapes all evidence so captured payloads can never execute when opened.
- Per-request `headers` and `follow_redirects` override on the HTTP client, plus
  a single automatic retry on transient transport errors (idempotent methods).
- **Scan resume** (`--resume <scan-id>`): the engine checkpoints after every
  stage (crawl, API discovery, each detector) in a new SQLite `checkpoints`
  table; an interrupted scan resumes from the first unfinished stage, reusing
  the crawled surface, API inventory and findings already produced. Completed
  scans delete their checkpoint.
- **Opt-in rate-limiting checks** (`--rate-limit-check` /
  `safety.rate_limit_checks`): a controlled, paced GET burst (capped at 30,
  interval-configurable) against authentication-looking endpoints only, stopping
  at the first HTTP 429/lockout signal and logging every attempt in evidence.
  Never enabled by default; never submits credentials.
- Lab app extended with vulnerable parameter endpoints (`/search`, `/go`,
  `/item`, `/download`), an auth-echo `/whoami`, an exposed `/openapi.json`, a
  `/graphql` endpoint with introspection enabled, a throttled `/login` (HTTP 429
  after N requests), and a permissive-CORS `/api/users` that leaks a
  password-hash field.

## [0.1.0] - 2026-08-05

Initial public foundation release (Phase 1).

### Added

- Shared core audit engine (`isahat.core`) used by every front-end.
- Safe, deny-by-default **scope** policy with per-request enforcement.
- Rate-limited, scope-aware, non-destructive **HTTP client**.
- Scope-bound **crawler** with endpoint inventory.
- Passive **technology fingerprinting**.
- Detectors: **security headers**, **insecure cookies**, **sensitive files**
  (non-destructive allowlist with content validation).
- Separate **severity** and **confidence** models; **risk** prioritisation.
- **JSON** and **Markdown** reporters; **scan comparison**.
- Local **SQLite** storage (`report`, `compare`, `list`).
- Automatic **secret masking** in evidence and reports.
- Typer-based **CLI**: `scan`, `report`, `compare`, `list`, `plugins`,
  `doctor`, `version`, with predictable exit codes for CI.
- Bundled **vulnerable lab app** for demos and tests.
- Unit and integration tests; `ruff` + `mypy` (strict) clean.
- Packaging (`pyproject.toml`), `Dockerfile`, `docker-compose.yml`, example
  `isahat.yml`, and GitHub Actions CI.
- Documentation: README, architecture, methodology, CLI, API, plugins, threat
  model, responsible-use, contributing, security policy, and ADRs.

[Unreleased]: https://github.com/aislamsilvalol-ctrl/isahat/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aislamsilvalol-ctrl/isahat/releases/tag/v0.1.0
