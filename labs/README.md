# Labs — intentionally vulnerable targets

These are **deliberately insecure** applications used by IsaHat's own tests and
for local demos. They exist so you can safely see IsaHat find real issues.

> ⚠️ Never deploy or expose these on a public network. Run them only on
> `localhost` / an isolated lab.

## `vulnerable_apps/simple_app`

A zero-dependency app (Python standard library only) that ships common
misconfigurations: missing security headers, an insecure session cookie, an
exposed `/.env` and `/.git/HEAD`, and a version-disclosing `Server` header.

```bash
python labs/vulnerable_apps/simple_app/app.py --port 8123
# then, in another terminal:
isahat scan http://127.0.0.1:8123 --yes --verbose
```

The end-to-end test in `tests/integration/test_engine_e2e.py` starts this app on
a loopback port and asserts IsaHat finds the expected issues.

## Roadmap

- `mock_apis/` — REST/GraphQL mock services for API-focused checks (Phase 2).
- `sample_targets/` — larger, realistic vulnerable apps for scenario testing.
