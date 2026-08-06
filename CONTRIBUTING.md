# Contributing to IsaHat

Thank you for helping build an open, trustworthy security auditor. This guide
gets you productive quickly and keeps the project consistent.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- IsaHat is a **defensive** tool. Contributions must not add destructive,
  evasive, or unauthorised-access capabilities. See
  [RESPONSIBLE-USE.md](RESPONSIBLE-USE.md).
- Every non-trivial change ships with **tests** and updated **docs**.

## Getting started

```bash
git clone https://github.com/aislamsilvalol-ctrl/isabellahat.git
cd isahat
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest            # run the suite
ruff check src tests
mypy
```

More detail in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Development workflow

1. **Open an issue** describing the change (bug, feature, detector, docs).
2. For significant design changes, propose an **ADR** in
   [`docs/adr/`](docs/adr/) using the template.
3. Create a branch: `feat/<short-name>` or `fix/<short-name>`.
4. Make focused commits using [Conventional Commits](#commit-messages).
5. Ensure `pytest`, `ruff` and `mypy` pass locally.
6. Open a Pull Request using the template. Link the issue.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(cli): add initial scan command
feat(scanner): implement security headers analyzer
fix(scope): prevent crawling outside allowed hosts
docs(readme): add local installation instructions
test(crawler): cover redirect scope validation
```

Scopes we use: `cli`, `core`, `scanner`, `scope`, `crawler`, `detectors`,
`reporting`, `storage`, `docs`, `ci`, `desktop`.

## Adding a detector

1. Create a module under `src/isahat/core/detectors/`.
2. Subclass `Detector` (see `detectors/base.py`), set `name`/`category`, and
   implement `async def run(self, ctx) -> list[Finding]`.
3. Emit `Finding`s with **honest severity and confidence** — never mark a result
   `CONFIRMED` without evidence.
4. Register it in `detectors/__init__.py::default_detectors` if it is safe by
   default.
5. Add tests in `tests/unit/test_detectors.py` (build synthetic responses; use
   `tests/unit/helpers.py`).

See [docs/SCANNING-METHODOLOGY.md](docs/SCANNING-METHODOLOGY.md) for the rules
detectors must follow.

## Code quality

- Type-annotate everything; `mypy` runs in **strict** mode.
- Keep modules small and cohesive; follow the existing structure.
- No secrets, no telemetry, no network calls in tests.
- Prefer clarity over cleverness.

## Pull request checklist

- [ ] Tests added/updated and passing
- [ ] `ruff` and `mypy` clean
- [ ] Docs/CHANGELOG updated
- [ ] Change respects the Responsible Use policy

## License of contributions

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE).
