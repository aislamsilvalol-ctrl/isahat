<div align="center">

# IsaHat

**Open Source AI Security Auditor for Vibe-Coded Applications**

Discover, validate, contextualise, prioritise and explain security issues in
modern web apps, APIs and systems — from your terminal or a graphical app,
sharing one audit engine.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/isahat/isahat/actions/workflows/ci.yml/badge.svg)](https://github.com/isahat/isahat/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

</div>

---

## What is IsaHat?

Applications increasingly ship with AI assistance ("vibe-coded"). They ship fast
— and often carry the same recurring weaknesses: incomplete authentication,
broken authorization, exposed secrets, weak APIs, missing validation, insecure
configuration and forgotten endpoints.

IsaHat is a professional, free and open-source auditor built to find those
issues **safely**. It does not just list alerts. For every finding it answers:
what it is, where it was found, the evidence, the confidence level, the likely
impact, whether it was actually confirmed, how to fix it, and how to verify the
fix.

> [!IMPORTANT]
> **Authorised use only.** IsaHat is a defensive tool. Use it exclusively on
> systems you own, development/staging environments, security labs, and targets
> you are formally authorised to test (including legitimate bug bounty scope).
> Read [RESPONSIBLE-USE.md](RESPONSIBLE-USE.md) before your first scan.

## Highlights

- **One engine, many front-ends.** The CLI (and the planned desktop app) are
  thin shells over `isahat.core`. No important capability lives in only one UI.
- **Safe by default.** `safe` profile, per-host rate limiting, mandatory scope
  confirmation, non-destructive checks, and automatic secret masking in evidence.
- **Severity *and* confidence, kept separate.** A `CRITICAL` finding with
  `POSSIBLE` confidence is never reported as confirmed.
- **Explainable findings.** CWE/OWASP mapping, impact, remediation example and
  references for each result.
- **Offline-first.** Local SQLite storage, no telemetry, works without internet
  once installed.

## Install

Requires Python 3.11+.

```bash
# from source (recommended during alpha)
git clone https://github.com/isahat/isahat.git
cd isahat
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

See [INSTALLATION.md](docs/INSTALLATION.md) for Docker, PyPI (planned) and CI usage.

## Quick start

```bash
# Audit a target you are authorised to test
isahat scan https://example.com

# API scan, JSON output, fail CI on high+ findings
isahat scan https://api.example.com --type api --format json --fail-on high

# Use a config file and write an HTML-free Markdown + JSON report
isahat scan https://example.com --format both -o report

# Review history
isahat list
isahat report <scan-id>
isahat compare <old-scan-id> <new-scan-id>

# Environment & detector health
isahat doctor
isahat plugins list
```

The full command reference lives in [docs/CLI.md](docs/CLI.md).

### Configuration (`isahat.yml`)

```yaml
project:
  name: example-app
target:
  url: https://example.com
  allowed_hosts:
    - example.com
    - api.example.com
scan:
  profile: safe
  concurrency: 5
  timeout: 10
  follow_redirects: true
scope:
  include:
    - /api/*
    - /dashboard/*
  exclude:
    - /logout
    - /delete-account
    - /payments/*
report:
  formats:
    - json
    - markdown
safety:
  destructive_tests: false
  rate_limit: 3
  require_scope_confirmation: true
```

A ready-to-copy file is in [`examples/isahat.yml`](examples/isahat.yml).

## What IsaHat checks today (Phase 1)

| Area | Checks |
| --- | --- |
| Security headers | Missing CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy; version disclosure |
| Session / cookies | Missing `Secure` / `HttpOnly` / `SameSite` on cookies |
| Sensitive files | Non-destructive allowlist probe (`.git/HEAD`, `.env`, `.DS_Store`, SQL backups) with content validation |
| Surface discovery | Scope-bound crawler, endpoint inventory, technology fingerprinting |

The [ROADMAP.md](ROADMAP.md) covers the web scanner (Phase 2), desktop app
(Phase 3), AI assistance (Phase 4) and the plugin/integration ecosystem
(Phase 5).

## Architecture

```
isahat/
├── src/isahat/
│   ├── core/          # the shared audit engine (scope, http, crawler, detectors, risk)
│   ├── cli/           # Typer CLI — a thin shell over core
│   ├── reporting/     # JSON / Markdown / comparison reporters
│   └── storage/       # local SQLite persistence
├── tests/             # offline unit tests
├── labs/              # intentionally vulnerable sample targets
├── docs/              # architecture, methodology, ADRs, guides
└── .github/           # CI, issue/PR templates
```

Design details and decisions are in [ARCHITECTURE.md](docs/ARCHITECTURE.md) and
the Architecture Decision Records under [`docs/adr/`](docs/adr/).

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security issues have a dedicated
process in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE). Rationale in
[docs/adr/0002-license.md](docs/adr/0002-license.md).
