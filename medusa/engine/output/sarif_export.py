"""SARIF 2.1 export."""
from __future__ import annotations

from medusa.engine.core.models import FindingModel

__all__ = ["to_sarif"]


def to_sarif(findings: list[FindingModel]) -> dict:
    """Return SARIF 2.1 JSON document."""
    results = []
    for i, f in enumerate(findings):
        results.append({
            "ruleId": f.module or "unknown",
            "level": "error" if f.severity in ("critical", "high") else "warning",
            "message": {"text": f.title or ""},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target or ""}}}],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Medusa", "version": "1.0.0"}},
            "results": results,
        }],
    }
