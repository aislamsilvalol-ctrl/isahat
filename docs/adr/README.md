# Architecture Decision Records (ADRs)

This directory records significant architectural decisions. Each ADR captures
the context, the problem, alternatives considered, the decision, consequences,
risks and whether it can be reversed.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-monorepo-and-shared-core.md) | Monorepo with a single shared core engine | Accepted |
| [0002](0002-license.md) | License: Apache-2.0 | Accepted |
| [0003](0003-storage.md) | Local storage: SQLite (stdlib) first | Accepted |
| [0004](0004-local-bridge-for-guis.md) | GUI access via a loopback FastAPI bridge | Accepted |

## Writing a new ADR

Copy [`template.md`](template.md), number it sequentially, fill it in, and add a
row to the index above in the same PR.
