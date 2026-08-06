# IsaHat Roadmap

This roadmap is a living document. Milestones map to GitHub Milestones; major
decisions are recorded as ADRs in [`docs/adr/`](docs/adr/).

Legend: ✅ done · 🚧 in progress · ⬜ planned

## Phase 1 — Foundation ✅ (current release: `0.1.0`)

- ✅ Monorepo structure and documentation
- ✅ Apache-2.0 license + responsible-use policy
- ✅ Shared core engine with an internal API
- ✅ Functional CLI (`scan`, `report`, `compare`, `list`, `plugins`, `doctor`)
- ✅ Safe scope definition and enforcement
- ✅ Basic scope-bound crawler
- ✅ Security headers analyzer
- ✅ Insecure cookie analyzer
- ✅ Sensitive files (non-destructive allowlist) analyzer
- ✅ Technology fingerprinting
- ✅ Endpoint inventory
- ✅ Severity + confidence classification and risk prioritisation
- ✅ JSON and Markdown reports; scan comparison
- ✅ SQLite persistence
- ✅ Unit + integration tests, GitHub Actions, Dockerfile

## Phase 2 — Web scanner 🚧

- ✅ Form and parameter discovery/analysis
- ✅ Injection-point model (safe, GET-only, capped)
- ✅ CORS misconfiguration checks
- ✅ Reflected XSS (safe marker payload, unencoded-reflection check)
- ✅ SQL Injection (error-based, non-destructive single-quote probe)
- ✅ Open Redirect (non-following Location probe)
- ✅ SARIF, CSV and HTML reporters
- ✅ Authentication/session handling (`--auth auth.json`)
- ✅ Path Traversal / LFI (read-only signature probe)
- ✅ API surface discovery (OpenAPI/Swagger + GraphQL) and API checks
  (introspection exposure, excessive data exposure)
- ✅ Rate-limiting checks (opt-in, controlled burst)
- ✅ Resume interrupted scans (`--resume`, stage checkpoints)
- ⬜ Boolean/time-based SQLi (opt-in), more injection classes
- ⬜ PDF reports

## Phase 3 — Desktop application 🚧

- ✅ Local FastAPI bridge over the shared engine (`isahat serve`): start scans,
  live progress (SSE), reports, comparison, health — loopback-only, same scope
  and sanitisation guarantees as the CLI
- ✅ Finding review workflow in the core: persistent false-positive / fixed /
  accepted-risk marking with comments, keyed by stable finding fingerprint so
  decisions survive re-scans
- ✅ Tauri + React + TypeScript shell (`apps/desktop`): dashboard with severity
  totals, audit history, new-audit form with authorisation checklist, live
  audit view (SSE), findings with filters and sanitized evidence, report
  export, audit comparison
- ⬜ Multi-target projects (grouping several authorised targets)
- ⬜ Native packaging & signed binaries for Windows/macOS/Linux
- ⬜ UI-level automated tests (Playwright/Vitest)

## Phase 4 — Intelligence ⬜

- ⬜ Finding de-duplication and grouping
- ⬜ Automated explanations and remediation suggestions
- ⬜ Context analysis and correlation between findings
- ⬜ Local models first (Ollama); optional external providers with consent
- ⬜ Full offline mode; AI fully disableable

## Phase 5 — Ecosystem ⬜

- ⬜ SDK and stable public API
- ⬜ Plugin system (manifest, permissions, checksum)
- ⬜ Integrations: GitHub Actions, GitLab, Jira, Linear, Slack, DefectDojo, ZAP,
  Burp, Semgrep, Trivy, Nuclei (safe mode)
- ⬜ Community plugin marketplace

## How to influence the roadmap

Open a GitHub Discussion or Issue. Substantial changes should come with an ADR
proposal. See [CONTRIBUTING.md](CONTRIBUTING.md).
