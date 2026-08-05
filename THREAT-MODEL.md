# IsaHat Threat Model

This document analyses the security of **IsaHat itself** — a security tool is a
high-value target and must hold itself to the standard it enforces on others.

## Assets

1. **Scan data** — findings, evidence, requests/responses. May contain sensitive
   information about the target even after masking.
2. **Credentials/auth material** — auth files imported for authenticated scans.
3. **Configuration** — scope definitions and target lists.
4. **The engine's authorisation boundary** — the scope policy that keeps IsaHat
   from touching unauthorised systems.

## Trust boundaries

```
[ User / CI ] -> [ CLI / Desktop ] -> [ core engine ] -> [ target under test ]
                                          |
                                          v
                                  [ local SQLite store ]
```

- The **target** is untrusted: its responses may be malicious (e.g. crafted to
  trigger ReDoS or huge payloads). Detectors must be defensive.
- **Plugins** (Phase 5) are semi-trusted and will run with declared permissions
  only.
- **AI providers** (Phase 4) are external trust boundaries; data leaving the
  machine must be explicit and consented.

## Threats and mitigations

| # | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T1 | IsaHat scans an unauthorised host | Deny-by-default scope, per-request checks, mandatory confirmation | Implemented |
| T2 | Destructive request sent to target | Only safe HTTP methods unless `destructive_tests` enabled | Implemented |
| T3 | Target overwhelmed (DoS) | Per-host rate limiting, bounded concurrency, page/depth caps | Implemented |
| T4 | Secrets persisted in scan store | Central sanitiser masks headers/tokens/keys before storage | Implemented |
| T5 | Malicious target response causes ReDoS/crash | Truncated evidence, bounded regex; detector errors isolated per-detector | Partial |
| T6 | Evidence leaks sensitive target data in reports | Masking + explicit truncation; report review guidance | Implemented |
| T7 | Malicious plugin exfiltrates data | Manifest + declared permissions + checksum (Phase 5) | Planned |
| T8 | Private code sent to external AI | AI off by default; explicit consent + local-first (Ollama) | Planned |
| T9 | Supply-chain compromise of IsaHat | Pinned deps, SAST, secret scanning, SBOM, signed releases in CI | In progress |
| T10 | Stored scan DB read by other local users | DB under `~/.isahat` with user perms; document encryption for shared hosts | Partial |

## Non-goals

- IsaHat is **not** an exploitation framework. It validates issues with
  controlled, non-destructive checks and does not weaponise findings.
- IsaHat does **not** attempt to evade WAFs, IDS/IPS or logging.

## Residual risks

- Aggressive rate limits can still add load; users must set limits appropriate to
  their target and authorisation.
- Masking is best-effort; unusual secret formats may slip through. Report gaps as
  security issues (see [SECURITY.md](SECURITY.md)).

This model evolves with the product; changes are tracked via ADRs in
[`docs/adr/`](docs/adr/).
