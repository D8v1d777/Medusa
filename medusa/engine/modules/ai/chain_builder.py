"""Attack chain builder — AI-synthesized attack paths."""
from __future__ import annotations

from dataclasses import dataclass, field

from medusa.engine.core.models import FindingModel  # noqa: F401
from medusa.engine.core.session import Session

__all__ = ["suggest_chains", "AttackChain", "ChainStep"]


@dataclass
class ChainStep:
    """Single step in attack chain."""

    finding_id: str
    action: str
    outcome: str


@dataclass
class AttackChain:
    """Attack chain with MITRE mapping."""

    name: str
    mitre_techniques: list[str]
    steps: list[ChainStep]
    likelihood: float
    impact: str
    prerequisites: list[str] = field(default_factory=list)


async def suggest_chains(session: Session) -> list[AttackChain]:
    """Synthesize attack chains from findings."""
    findings = session.db_session.query(FindingModel).filter_by(
        session_id=session.id
    ).all()
    high = [f for f in findings if f.severity in ("critical", "high")]
    if not high:
        return []
    return [
        AttackChain(
            name=f"Chain from {high[0].title}",
            mitre_techniques=["T1190"],
            steps=[
                ChainStep(
                    finding_id=str(high[0].id),
                    action="Exploit",
                    outcome="Initial access",
                )
            ],
            likelihood=0.7,
            impact="High",
        )
    ]
