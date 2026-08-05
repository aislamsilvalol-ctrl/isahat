"""Reports GraphQL endpoints with introspection left enabled.

Discovery already confirmed the endpoint by running a read-only introspection
probe, so this detector works purely off ``ctx.apis`` — no extra traffic. In
production, introspection hands attackers a complete map of queries, mutations
and types, making targeted abuse far easier.
"""

from __future__ import annotations

from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.models import Confidence, Evidence, Finding, Severity


class GraphqlIntrospectionDetector(Detector):
    name = "graphql-introspection"
    category = "API Security"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for api in ctx.apis:
            if api.kind != "graphql":
                continue
            types = ", ".join(
                op.removeprefix("type: ") for op in api.operations if op.startswith("type: ")
            )
            findings.append(
                Finding(
                    title="GraphQL introspection enabled",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    cwe="CWE-200",
                    owasp="API8:2023 Security Misconfiguration",
                    endpoint=api.url,
                    method="GET",
                    evidence=Evidence(
                        summary=(
                            "A read-only introspection query returned the schema: "
                            f"{api.operation_count} type(s) discovered"
                            + (f" ({types})" if types else "")
                            + "."
                        ),
                        response=f"types: {types}" if types else None,
                        location=api.url,
                    ),
                    impact=(
                        "Introspection exposes the full schema (queries, mutations, types), "
                        "giving attackers a precise map for crafting targeted queries, finding "
                        "deprecated/undocumented fields and planning BOLA or data-exposure abuse."
                    ),
                    likelihood="medium",
                    exploitation="Anyone can fetch the schema with a single introspection query.",
                    recommendation=(
                        "Disable introspection in production (or gate it behind auth). Enforce "
                        "query depth/complexity limits and persist allowed queries where possible."
                    ),
                    remediation_example=(
                        "# Apollo Server\nnew ApolloServer({ introspection: process.env.NODE_ENV"
                        " !== 'production' })"
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    ],
                    false_positive_hints=[
                        "Intentional on public, schema-documented APIs and in non-production.",
                    ],
                )
            )
        return findings
