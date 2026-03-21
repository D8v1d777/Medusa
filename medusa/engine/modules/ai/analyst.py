"""AI analyst — per-finding deep analysis."""
from __future__ import annotations

from dataclasses import dataclass

from medusa.engine.core.models import FindingModel

__all__ = ["explain", "FindingAnalysis"]


@dataclass
class FindingAnalysis:
    """AI analysis result."""

    technical_explanation: str
    business_impact: str
    remediation_steps: list[str]
    cvss_justification: str
    owasp_category: str
    cwe_ids: list[str]
    references: list[str]


async def explain(
    finding: FindingModel,
    sitemap: object | None,
    session: object,
) -> FindingAnalysis:
    """Generate technical explanation and remediation."""
    return FindingAnalysis(
        technical_explanation=finding.description or "",
        business_impact="Potential impact depends on asset criticality.",
        remediation_steps=["Review and fix the identified vulnerability."],
        cvss_justification="Based on standard CVSS scoring.",
        owasp_category="A03:2021-Injection",
        cwe_ids=[],
        references=[],
    )
