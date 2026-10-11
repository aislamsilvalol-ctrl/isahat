# Labs — intentionally vulnerable targets

These are **deliberately insecure** applications used by IsaHat's own tests and
for local demos. They exist so you can safely see IsaHat find real issues.

> ⚠️ Never deploy or expose these on a public network. Run them only on
> `localhost` / an isolated lab.

## `vulnerable_apps/simple_app`

A zero-dependency app (Python standard library only) that ships common
misconfigurations: missing security headers, an insecure session cookie, an
exposed `/.env` and `/.git/HEAD`, a version-disclosing `Server` header, an
OpenAPI document, and a GraphQL endpoint that answers introspection.

```bash
python labs/vulnerable_apps/simple_app/app.py --port 8123
# then, in another terminal:
isahat scan http://127.0.0.1:8123 --yes --verbose
```

The end-to-end test in `tests/integration/test_engine_e2e.py` starts this app on
a loopback port and asserts IsaHat finds the expected issues.

This is the only lab target in the repository. `mock_apis/` and
`sample_targets/` are not included, and there is no command that installs them.
