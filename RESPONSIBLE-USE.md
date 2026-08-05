# Responsible Use Policy

IsaHat is a **defensive** security tool. It exists to help you find and fix
vulnerabilities in systems you are responsible for — before someone else finds
them. Using it against systems you are not authorised to test is illegal in most
jurisdictions and against the spirit of this project.

## You may use IsaHat on

- Systems you **own**.
- **Development**, **staging** and **homologation** environments.
- **Security labs** and intentionally vulnerable practice targets.
- Applications for which you hold **explicit, written authorisation**.
- Targets that are **in scope** for a **legitimate bug bounty program**.
- Infrastructure whose owner has **authorised** the testing.

## You must not use IsaHat to

- Test systems without authorisation.
- Cause **downtime** or degrade availability.
- **Delete**, **alter** or corrupt real data.
- Deploy ransomware, backdoors or **persistence**.
- **Steal**, harvest or **exfiltrate** credentials or data.
- Exceed the **authorised scope**.
- Automate **destructive** attacks.
- **Hide** activity or **evade** security controls.

## How IsaHat enforces safety

These are not just guidelines — they are built into the engine:

| Control | Where |
| --- | --- |
| Scope is deny-by-default; every request is checked | `core/scope.py` |
| Only non-destructive methods (GET/HEAD/OPTIONS) unless explicitly enabled | `core/http.py` |
| Per-host rate limiting | `core/http.py` |
| Mandatory scope confirmation before scanning | `cli/main.py` |
| Secrets masked before storage/reporting | `core/sanitize.py` |
| Honest, identifying `User-Agent` (no evasion) | `core/http.py` |
| Business-logic and brute-force tests require explicit opt-in (Phase 2+) | roadmap |

## Brute-force and rate-limit testing

When implemented, resistance testing (rate limiting, lockout, CAPTCHA, OTP
protection, user enumeration) will always:

- use a **low** attempt limit and a configurable interval;
- operate only on a **provided list of test accounts**;
- require **explicit confirmation**;
- stop automatically on protection triggers;
- never use leaked credential lists;
- never target real accounts without specific authorisation.

## Reporting misuse

If you believe IsaHat is being used to attack systems, or you find a security
issue in IsaHat itself, see [SECURITY.md](SECURITY.md).

By using IsaHat you accept sole responsibility for ensuring you are authorised
to test any target you point it at.
