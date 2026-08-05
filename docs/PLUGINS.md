# Plugins & Detectors

Detectors are the units of analysis in IsaHat. Built-in detectors and future
third-party plugins share the same `Detector` contract, so anything you can do
in a plugin, the core already does.

> The **external plugin system** (discovery, install, manifest, permissions,
> checksum) lands in Phase 5. Today you extend IsaHat by adding a detector in
> the codebase or registering one programmatically.

## The `Detector` contract

```python
from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity

class MyDetector(Detector):
    name = "my-detector"
    category = "Security Misconfiguration"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for response in ctx.responses:          # traffic already captured
            if "x-powered-by" in response.headers:
                findings.append(Finding(
                    title="Framework disclosed",
                    category=self.category,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    endpoint=response.url,
                    evidence=Evidence(summary="X-Powered-By present"),
                    impact="Aids fingerprinting.",
                    recommendation="Remove the header.",
                ))
        return findings
```

### `DetectorContext`

| Field | Description |
| --- | --- |
| `target` | The scan target URL. |
| `scope` | The authorised `Scope` — always check before new requests. |
| `client` | A `SafeHttpClient` for **scoped, non-destructive** requests. |
| `responses` | Traffic captured by the crawler (for passive detectors). |
| `destructive` | Whether destructive tests are enabled (default `False`). |

### Passive vs active detectors

- **Passive** detectors only read `ctx.responses` — preferred, zero extra load.
- **Active** detectors may call `ctx.client.get(url)` but **must**:
  - stay within `ctx.scope` (the client enforces this);
  - use only non-destructive methods;
  - validate results to keep confidence honest.

## Rules every detector must follow

1. **Never** mark a finding `CONFIRMED` without evidence.
2. Keep **severity** and **confidence** independent and honest.
3. **Mask secrets** in evidence via `isahat.core.sanitize`.
4. Do not raise on ordinary target behaviour; the engine isolates failures but
   detectors should be defensive (bounded parsing, no unbounded regex).
5. Provide `impact`, `recommendation`, and where possible a remediation example
   and references.

## Registering a detector

Add it to `default_detectors()` in `src/isahat/core/detectors/__init__.py` if it
is safe by default, or pass a custom list to the engine:

```python
from isahat.core import ScanEngine, ScanConfig
engine = ScanEngine("https://example.com", ScanConfig(), detectors=[MyDetector()])
```

## Planned plugin manifest (Phase 5)

External plugins will ship a manifest declaring:

- name, version, author, license
- requested permissions (network, filesystem, AI)
- dependencies and compatibility range
- checksum/signature
- documentation and tests

Plugins will run with **only** their declared permissions — no unrestricted
system access.
