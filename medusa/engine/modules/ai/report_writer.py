"""Report writer — streaming narrative generation."""
from __future__ import annotations

from medusa.engine.core.session import Session
from medusa.engine.modules.ai.analyst import FindingAnalysis

__all__ = ["write_executive_summary", "write_technical_narrative"]


async def write_executive_summary(session: Session) -> str:
    """Stream executive summary (400-600 words)."""
    from medusa.engine.core.models import FindingModel
    count = session.db_session.query(FindingModel).filter_by(
        session_id=session.id
    ).count()
    return f"""Executive Summary

This engagement identified {count} potential security findings for {session.model.name}.
Scope included the target environment. Findings are prioritized by severity.

Recommendations:
- Address critical and high severity issues first
- Implement defensive controls as outlined in the Blue Team report
"""


async def write_technical_narrative(
    finding: object, analysis: FindingAnalysis
) -> str:
    """Write technical narrative for one finding."""
    return f"""Technical Narrative

{analysis.technical_explanation}

Remediation:
{chr(10).join(f'- {s}' for s in analysis.remediation_steps)}
"""
