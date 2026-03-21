"""Hardening advisor — actionable recommendations."""
from __future__ import annotations

from dataclasses import dataclass, field

from medusa.engine.core.models import FindingModel, SessionModel

__all__ = ["HardeningAdvisor", "HardeningReport", "HardeningItem"]

@dataclass
class HardeningItem:
    """Single hardening recommendation."""

    category: str
    title: str
    finding_ids: list[str]
    current_state: str
    recommended_control: str
    implementation_effort: str
    verification_method: str
    priority_score: float
    compliance_mapping: str = ""


@dataclass
class HardeningReport:
    """Full hardening report."""

    session_id: str
    items: list[HardeningItem] = field(default_factory=list)


class HardeningAdvisor:
    """Generates hardening recommendations from findings."""

    async def advise(
        self, findings: list[FindingModel], session: SessionModel
    ) -> HardeningReport:
        """Group findings by category and generate hardening items."""
        report = HardeningReport(session_id=str(session.id))
        categories = {}
        for f in findings:
            cat = "Application"
            if "network" in (f.module or ""):
                cat = "Network"
            elif "auth" in (f.module or ""):
                cat = "Identity"
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f)

        for cat, flist in categories.items():
            max_cvss = max((f.cvss_score or 0 for f in flist), default=0)
            effort = "Low" if max_cvss < 5 else "Medium" if max_cvss < 8 else "High"
            report.items.append(
                HardeningItem(
                    category=cat,
                    title=f"Address {len(flist)} findings in {cat}",
                    finding_ids=[str(f.id) for f in flist],
                    current_state="Vulnerabilities confirmed by scan",
                    recommended_control="Apply patches, harden config, validate input",
                    implementation_effort=effort,
                    verification_method="Re-scan after changes",
                    priority_score=max_cvss,
                )
            )
        return report
