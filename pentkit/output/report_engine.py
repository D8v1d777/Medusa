import json
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from pentkit.core.session import Session, SessionModel, FindingModel
from pentkit.core.logger import get_module_logger
from pentkit.core.ai_engine import AIEngine

logger = get_module_logger("output.report_engine")

class ReportEngine:
    """
    Precision Report Engine with AI narrative generation (GAP 8).
    """
    def __init__(self, ai: Optional[AIEngine] = None):
        self.template_dir = Path("pentkit/templates")
        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))
        self.ai = ai

    async def generate_full_report(self, session: Session, out_path: Optional[str] = None):
        """Generate a full technical report with AI-anchored narratives (GAP 8)."""
        logger.info(f"Generating full report for session {session.id}")
        
        # 1. AI Executive Summary (GAP 8)
        exec_summary = "Executive summary pending AI analysis."
        if self.ai:
            exec_summary = await self._generate_ai_executive_summary(session)

        # 2. AI Finding Narratives (GAP 8)
        findings = []
        for f in session.model.findings:
            narrative = f.description
            if self.ai and f.severity in ["high", "critical"]:
                narrative = await self._generate_ai_finding_narrative(f)
            
            findings.append({
                "module": f.module,
                "target": f.target,
                "title": f.title,
                "severity": f.severity,
                "description": narrative,
                "payload": f.payload,
                "request": f.request,
                "response": f.response,
                "cvss_vector": f.cvss_vector,
                "details": f.details,
                "confidence": f.confidence,
                "notes": f.notes
            })
        
        # Render template...
        # ... rest of generate_full_report ...

    async def _generate_ai_executive_summary(self, session: Session) -> str:
        """Generate evidence-anchored executive summary (GAP 8)."""
        # Collect context
        crit_findings = [f for f in session.model.findings if f.severity in ["critical", "high"]]
        
        system = (
            f"You are writing an executive summary for {session.model.name}. "
            "Every risk statement must reference a specific finding by ID. "
            "No generic security advice. First paragraph must state the single most impactful finding."
        )
        user = f"Findings: {[f.title for f in crit_findings[:5]]}\nTotal Findings: {len(session.model.findings)}"
        
        try:
            return await self.ai.complete(system, user)
        except:
            return "AI Executive Summary generation failed."

    async def _generate_ai_finding_narrative(self, finding: FindingModel) -> str:
        """Generate detailed technical narrative for a finding (GAP 8)."""
        system = (
            "You are writing a technical finding narrative. "
            "Audience: Developers. Include reproduction steps and root cause analysis. "
            "Be specific about the framework/language used by the target."
        )
        user = f"Finding: {finding.title}\nTarget: {finding.target}\nPayload: {finding.payload}\nResponse: {finding.response[:500]}"
        
        try:
            return await self.ai.complete(system, user)
        except:
            return finding.description

    def generate_exec_report(self, session: Session, out_path: Optional[str] = None):
        """Generate an executive summary report."""
        # Implementation similar to generate_full_report but with a different template
        pass

    def export_json(self, session: Session, out_path: Optional[str] = None):
        """Export findings to a JSON file."""
        findings = [
            {
                "id": f.id,
                "module": f.module,
                "target": f.target,
                "severity": f.severity,
                "payload": f.payload,
                "request": f.request,
                "response": f.response,
                "cvss_vector": f.cvss_vector,
                "details": f.details
            } for f in session.model.findings
        ]
        
        if not out_path:
            reports_dir = Path.home() / ".pentkit" / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            out_path = str(reports_dir / f"findings_{session.id}.json")
            
        with open(out_path, 'w') as f:
            json.dump(findings, f, indent=2)
        
        logger.info(f"JSON findings exported to: {out_path}")
        return out_path
