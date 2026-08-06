# Development Guide

## Prerequisites

- Python 3.11+
- git

## Setup

```bash
git clone https://github.com/aislamsilvalol-ctrl/isabellahat.git
cd isahat
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Everyday commands

```bash
pytest                      # run all tests
pytest tests/unit -q        # unit only
pytest -k scope             # filter by name
ruff check src tests        # lint
ruff check --fix src tests  # autofix
mypy                        # strict type check
```

## Try it against the bundled lab

```bash
# Terminal 1 — start the intentionally vulnerable app
python labs/vulnerable_apps/simple_app/app.py --port 8123

# Terminal 2 — scan it
isahat scan http://127.0.0.1:8123 --yes --verbose
```

## Project layout

```
src/isahat/
  core/        # the shared engine (see docs/ARCHITECTURE.md)
  cli/         # Typer CLI (presentation only)
  reporting/   # json / markdown / diff
  storage/     # SQLite
tests/
  unit/        # offline, fast
  integration/ # spins up the lab app on loopback
labs/          # intentionally vulnerable targets
docs/          # docs + ADRs
```

## Coding standards

- **Types everywhere**; `mypy` runs in strict mode.
- **No network in unit tests**; use synthetic responses / the lab app.
- **Secrets never persisted**; route evidence through `core/sanitize`.
- Keep the repo **executable at every commit**.
- Follow [Conventional Commits](https://www.conventionalcommits.org/).

## Adding functionality

- New check → add a **detector** (see [PLUGINS.md](PLUGINS.md)).
- New output → add a **reporter** in `isahat/reporting`.
- New behaviour that changes design → propose an **ADR** in
  [`adr/`](adr/) first.

## Releasing (maintainers)

1. Update `CHANGELOG.md` and bump the version in `pyproject.toml` and
   `src/isahat/__init__.py`.
2. Tag `vX.Y.Z`; CI builds artefacts and (later) publishes.
3. Draft GitHub Release notes from the changelog.

## Continuous integration

`.github/workflows/ci.yml` runs lint, type-check and tests on every push/PR
across supported Python versions. PRs must be green to merge.
