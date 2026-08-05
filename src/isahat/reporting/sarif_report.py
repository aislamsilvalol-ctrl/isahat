"""SARIF 2.1.0 reporter for CI and code-scanning integrations.

Emits a minimal but valid SARIF log so IsaHat findings can be uploaded to
GitHub code scanning and other SARIF-aware tools.
"""

from __future__ import annotations

import json
from typing import Any

from isahat import __version__
from isahat.core.models import ScanResult, Severity
from isahat.core.risk import priority_score

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        rule_id = finding.cwe or finding.category
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.category.replace(" ", ""),
                "shortDescription": {"text": finding.category},
                "helpUri": finding.references[0] if finding.references else None,
                "properties": {"category": finding.category},
            }
            if rules[rule_id]["helpUri"] is None:
                del rules[rule_id]["helpUri"]

        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": f"{finding.title}. {finding.evidence.summary}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.endpoint},
                        }
                    }
                ],
                "properties": {
                    "isahatId": finding.id,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "priority": priority_score(finding),
                    "owasp": finding.owasp,
                    "cwe": finding.cwe,
                    "method": finding.method,
                    "parameter": finding.parameter,
                    "recommendation": finding.recommendation,
                },
            }
        )

    log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "IsaHat",
                        "informationUri": "https://github.com/isahat/isahat",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "scanId": result.id,
                    "target": result.target,
                    "profile": result.profile,
                },
            }
        ],
    }
    return json.dumps(log, indent=2)
