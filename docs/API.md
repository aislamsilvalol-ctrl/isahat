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

## A note on the future HTTP API

Phase 3 introduces a local FastAPI bridge so the desktop app (and third parties)
can drive the engine over HTTP. It will mirror this in-process API 1:1.
