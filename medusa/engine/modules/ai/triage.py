"""AI triage — deduplication and severity adjustment."""
from __future__ import annotations

import logging

from medusa.engine.core.models import FindingModel
from medusa.engine.core.session import Session

__all__ = ["triage"]

logger = logging.getLogger(__name__)


async def triage(
    findings: list[FindingModel], session: Session
) -> list[FindingModel]:
    """Deduplicate and severity-adjust findings using AI."""
    if not findings:
        return []
    seen: dict[tuple[str, str], FindingModel] = {}
    for f in findings:
        target_val: str = str(getattr(f, "target", None) or "")
        title_val: str = str(getattr(f, "title", None) or "")
        key = (target_val, title_val)
        existing = seen.get(key)
        cvss_f: float = float(getattr(f, "cvss_score", None) or 0)
        cvss_existing: float = (
            float(getattr(existing, "cvss_score", None) or 0) if existing else 0.0
        )
        if existing is None or cvss_f > cvss_existing:
            seen[key] = f
    return list(seen.values())
