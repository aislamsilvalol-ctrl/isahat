# Internal API

IsaHat exposes a stable, in-process Python API under `isahat.core`. The CLI is
built on exactly this API; so are future front-ends.

> Status: `0.x` alpha. The API may change before `1.0`, but the model contracts
> in `isahat.core.models` are intended to be the most stable part.

## Running a scan programmatically

```python
from isahat.core import ScanConfig, ScanEngine

config = ScanConfig()
config.target.allowed_hosts = ["example.com"]
config.safety.require_scope_confirmation = False  # you assert authorisation

engine = ScanEngine("https://example.com", config)
result = engine.scan()          # blocking; or: await engine.run()

print(result.stats.findings_total)
for finding in result.findings:
    print(finding.severity.value, finding.confidence.value, finding.title)
```

### Async usage

```python
import asyncio
from isahat.core import ScanConfig, ScanEngine

async def main():
    engine = ScanEngine("https://example.com", ScanConfig(...))
    result = await engine.run()
    return result

asyncio.run(main())
```

## Rendering reports

```python
from isahat.reporting import to_json, to_markdown, to_html, render

json_text = to_json(result)
md_text = to_markdown(result)
html_text = to_html(result)               # self-contained, script-free
same = render(result, "sarif")            # or "csv", "html", "json", "markdown"
```

## Authenticated scans

```python
from isahat.core import AuthConfig, ScanConfig, ScanEngine, load_auth

auth = load_auth("auth.json")             # or AuthConfig(cookies={"session": "..."})
engine = ScanEngine("https://example.com", ScanConfig(), auth=auth)
```

## API surface discovery

```python
from isahat.core.api import discover_apis

apis = await discover_apis(client, "https://example.com")   # list[ApiSpec]
for api in apis:
    print(api.kind, api.url, api.operation_count, api.operations)
```

## Persistence

```python
from isahat.storage import ScanStore

with ScanStore() as store:      # ~/.isahat/isahat.db by default
    store.save(result)
    loaded = store.get(result.id)
    recent = store.list(limit=10)
```

## Comparing scans

```python
from isahat.reporting import compare_scans, diff_to_markdown

diff = compare_scans(old_result, new_result)
print(diff.summary)             # "1 new, 2 resolved, 3 unchanged"
print(diff_to_markdown(diff))
```

## Key types (`isahat.core.models`)

| Type | Notes |
| --- | --- |
| `ScanResult` | Full serialisable outcome; `recompute_stats()`, `findings_at_or_above()`. |
| `Finding` | `severity` + `confidence` kept separate; stable `fingerprint()` id. |
| `Endpoint` | Discovered surface item. |
| `Technology` | Detected framework/server. |
| `Severity` | `CRITICAL > HIGH > MEDIUM > LOW > INFO` (compare via `.rank`). |
| `Confidence` | `POSSIBLE`, `PROBABLE`, `HIGH`, `CONFIRMED`, `FALSE_POSITIVE`. |
| `FindingState` | `OPEN`, `FALSE_POSITIVE`, `FIXED`, `ACCEPTED_RISK`. |

## Writing a detector

See [PLUGINS.md](PLUGINS.md) and `isahat.core.detectors.base.Detector`.

## The local bridge API (HTTP)

Since Phase 3, the engine is also reachable over loopback HTTP for front-ends
(desktop app, future web UI). Start it with `isahat serve`; the application
factory is `isahat.api.create_app(db_path, config_path=...)`, which is fully
covered by `tests/unit/test_api_bridge.py`.

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Liveness + engine version. |
| `POST /scans` | Start a scan. Body: `target`, `profile`, `scan_type`, optional `auth`, `rate_limit_check`, and **required** `confirmed: true` (the client must show the authorisation banner first). Returns `202` + `scan_id`. |
| `GET /scans` | Scan history (newest first), with `running` flags. |
| `GET /scans/{id}` | Full `ScanResult` JSON with stored review annotations applied. |
| `GET /scans/{id}/status` | `running`/`done`/`error` plus the progress event buffer. |
| `GET /scans/{id}/events` | SSE stream of progress events; ends with a terminal `done`/`error` event. |
| `GET /scans/{id}/report?fmt=` | Rendered report download (`json`, `markdown`, `html`, `csv`, `sarif`). |
| `POST /scans/{id}/findings/{fid}/annotation` | Set review state (`fixed`, `false_positive`, `accepted_risk`, `open`) + optional comment. |
| `GET /compare?base=&head=` | Finding-id diff (new/resolved/unchanged) + markdown summary. |

Safety notes: the bridge is loopback-only by default; CORS is restricted to
localhost and Tauri origins; scope enforcement, rate limiting and evidence
sanitisation all happen inside the core, so no HTTP client can bypass them.
