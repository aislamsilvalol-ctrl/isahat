# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/isahat/isahat/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/isahat/isahat/releases/tag/v0.1.0
