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

- ⬜ Form and parameter discovery/analysis
- ⬜ API surface (REST) discovery
- ⬜ Authentication/session handling (`--auth auth.json`)
- ⬜ CORS misconfiguration checks
- ⬜ Reflected XSS (safe, controlled payloads)
- ⬜ SQL Injection (controlled, non-destructive)
- ⬜ Open Redirect
- ⬜ Path Traversal
- ⬜ Rate-limiting checks (opt-in)
- ⬜ SARIF and CSV reporters; HTML/PDF reports
- ⬜ Resume/cancel long scans (`--resume`)

## Phase 3 — Desktop application ⬜

- ⬜ Tauri + React + TypeScript shell over the core (via a local FastAPI bridge)
- ⬜ Projects, targets, scope, auth import
- ⬜ Live findings, filters, evidence viewer
- ⬜ Reports, history, scan comparison
- ⬜ False-positive / fixed marking, comments

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
