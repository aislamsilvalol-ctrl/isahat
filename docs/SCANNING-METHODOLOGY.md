# Scanning Methodology

IsaHat is designed to think like an experienced security engineer, not just emit
alerts. This document explains how it discovers, validates, classifies and
prioritises issues — safely.

## Principles

For every finding, IsaHat aims to answer:

1. What is the vulnerability?
2. Where was it found?
3. What is the evidence?
4. What is the confidence level?
5. What is the likely impact?
6. Was it actually confirmed, or could it be a false positive?
7. Could it combine with another finding?
8. What is the fix priority?
9. How does the developer fix it?
10. How can the fix be verified?

## Safety model

- **Deny-by-default scope.** Every request is checked against the authorised
  hosts and path rules before it is sent.
- **Non-destructive only.** The safe profile uses `GET`/`HEAD`/`OPTIONS`. No
  data is created, modified or deleted.
- **Rate limited.** Requests are spaced per host; concurrency is bounded.
- **No evasion.** IsaHat identifies itself honestly and does not try to bypass
  security controls.
- **Secrets masked.** Evidence is sanitised before storage or reporting.

## The pipeline

1. **Scope resolution** — derive allowed hosts from the target + config.
2. **Discovery/crawl** — breadth-first within scope, capturing responses and
   recording endpoints (including in-scope-but-excluded paths as surface only).
3. **Fingerprinting** — passive technology detection from headers, cookies and
   HTML.
4. **Detection** — each detector inspects captured traffic (and, for active
   detectors, makes additional scoped requests) to produce findings.
5. **Validation** — detectors attach evidence and set a confidence level that
   reflects how strongly the issue is proven.
6. **Prioritisation** — severity × confidence yields a 0–100 priority score.

## Severity vs confidence

These are **separate axes** and always reported together.

Severity — impact if exploited:

| Level | Meaning |
| --- | --- |
| Critical | Full compromise, RCE, mass data exposure, auth bypass, admin/infra control. |
| High | Significant impact with a viable path to exploitation. |
| Medium | Requires additional conditions or has limited impact. |
| Low | Minor impact or hardening. |
| Informative | Useful observation, no confirmed vulnerability. |

Confidence — how sure we are it is real:

| Level | Meaning |
| --- | --- |
| Possible | Weak signal; needs manual review. |
| Probable | Multiple indicators, not proven. |
| High | Strong indicators, near-certain. |
| Confirmed | Proven with direct evidence. |
| False positive | Verified not to be an issue. |

> A `Critical / Possible` finding is **not** the same as `Critical / Confirmed`.
> IsaHat never claims confirmation without evidence.

## Priority scoring

`priority = severity_weight × confidence_factor`, rounded to 0–100. Findings are
sorted by priority (then severity, then title) so the fix order is obvious.
See `isahat.core.risk`.

## What Phase 1 checks

| Category | Detector | Method |
| --- | --- | --- |
| Security misconfiguration | Missing CSP/HSTS/X-Content-Type-Options/X-Frame-Options/Referrer-Policy | Passive header analysis |
| Information disclosure | Version banners (`Server`, `X-Powered-By`, …) | Passive header analysis |
| Session management | Insecure cookies (Secure/HttpOnly/SameSite) | Passive `Set-Cookie` analysis |
| Sensitive data exposure | `.git/HEAD`, `.env`, `.DS_Store`, SQL backups | Active allowlist GET + content signature |

Later phases add authentication, authorization, injection (controlled), CORS,
XSS (safe payloads), API-specific checks and business-logic tests (opt-in). See
[ROADMAP.md](../ROADMAP.md).

## Reducing false positives

- Header findings analyse representative documents, not every asset.
- The sensitive-files detector ignores HTML "soft 404"/SPA fallbacks and
  validates content signatures before reporting.
- Findings carry `false_positive_hints` where relevant.

## Verifying a fix

Re-run the scan and use `isahat compare <old-id> <new-id>` to confirm the
finding moved to **resolved**. Each finding also lists a concrete remediation
example to validate against.
