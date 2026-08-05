# Security Policy

## Reporting a vulnerability in IsaHat

We take the security of IsaHat seriously. If you discover a vulnerability in the
tool itself, please report it privately.

- **Preferred:** open a [GitHub Security Advisory](https://github.com/isahat/isahat/security/advisories/new)
  (private, coordinated disclosure).
- **Alternative:** email `security@isahat.dev` with details.

Please **do not** open a public issue for security vulnerabilities.

### What to include

- A clear description of the issue and its impact.
- Steps to reproduce (a minimal PoC if possible).
- Affected version(s) / commit.
- Any suggested remediation.

### Our commitment

- We acknowledge reports within **72 hours**.
- We provide a remediation timeline after triage.
- We credit reporters (unless you prefer to remain anonymous).
- We coordinate disclosure and publish an advisory with a fix.

## Supported versions

IsaHat is in **alpha** (`0.x`). During alpha, only the latest release on `main`
receives security fixes. A formal support matrix will be published at `1.0`.

| Version | Supported |
| --- | --- |
| `0.1.x` (latest) | ✅ |
| older | ❌ |

## Scope

This policy covers the IsaHat codebase (engine, CLI, packaging, docs). Issues in
**third-party dependencies** should be reported upstream; if IsaHat can mitigate
them, we welcome a report too.

## Reporting misuse of IsaHat

If you believe IsaHat is being used against systems without authorisation, see
[RESPONSIBLE-USE.md](RESPONSIBLE-USE.md).
