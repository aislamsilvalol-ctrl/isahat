# ADR-0002: License — Apache-2.0

- **Status:** Accepted
- **Date:** 2026-08-05
- **Deciders:** IsaHat maintainers

## Context

IsaHat is an open-source security tool intended for broad adoption by developers
and security teams, and for a healthy contributor and plugin ecosystem.

## Problem

Which open-source license best protects the project's openness while maximising
legitimate adoption and contributions?

## Alternatives considered

- **GNU GPLv3** — strong copyleft. Ensures derivatives stay open, but its
  copyleft can deter integration into some commercial/internal toolchains and
  complicates plugin/SDK linking.
- **GNU AGPLv3** — closes the "network use" gap (SaaS must share source). Great
  for keeping hosted forks open, but the most restrictive for adopters and often
  blocked by corporate policies — a real barrier for a tool teams embed in CI.
- **Apache License 2.0** — permissive, with an explicit **patent grant** and
  trademark protections. Maximises adoption, is friendly to plugins/SDKs and
  enterprise CI use, and is widely trusted in the security tooling space.

## Decision

License IsaHat under the **Apache License 2.0**.

Rationale: for a defensive tool we want the widest possible legitimate use —
inside companies, CI pipelines, and other open-source projects — plus the
explicit patent grant that Apache-2.0 provides. This lowers the barrier to
adoption and to building an ecosystem of integrations and plugins.

## Consequences

- **Positive:** easy to adopt and integrate; explicit patent grant; compatible
  with a permissive plugin/SDK ecosystem; trusted by enterprises.
- **Negative:** does not force downstream forks (including SaaS) to publish
  their changes; a closed fork is legally permitted (must retain notices).

## Risks

- A vendor could build a closed product on top of IsaHat. We accept this trade
  in exchange for adoption; community momentum and trademark protection are our
  primary defences of the project's openness.

## Reversibility

Hard to reverse for already-released code (existing versions remain Apache-2.0).
Future versions could adopt a different license, but this would require
contributor agreement and would fragment the community, so it is unlikely.
