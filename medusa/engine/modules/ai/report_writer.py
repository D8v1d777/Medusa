"""
Report writer — TIER 3.
AI-generated professional narrative:
- Executive summary (400-600 words, non-technical)
- Technical narrative per finding
- OWASP Top 10 coverage analysis
- Blue team recommendations
- SARIF export preparation
- Jira export preparation
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from medusa.engine.core.models import FindingModel
from medusa.engine.core.session import Session
from medusa.engine.modules.ai.analyst import FindingAnalysis

__all__ = ["write_executive_summary", "write_technical_narrative", "ReportWriter"]

logger = logging.getLogger(__name__)

EXECUTIVE_PROMPT = """You are a CISO-level security consultant writing an executive summary for a board-level audience.
No technical jargon. Focus on business risk, potential impact, and prioritized remediation.
Write 400-600 words. Be direct and professional. Output plain text, no markdown."""

TECHNICAL_PROMPT = """You are a senior penetration tester writing a technical finding narrative.
Write clearly for a developer audience who needs to reproduce and fix this vulnerability.
Include: what it is, how it was found, how to reproduce, why it's dangerous, how to fix it.
Output plain text, 200-400 words."""

SUMMARY_PROMPT = """You are a security analyst writing a scan summary report section.
Summarize the findings concisely. Group by OWASP category. Highlight critical and high items.
Output plain text, 300-500 words."""


class ReportWriter:
    """Generates professional security reports from scan findings."""

    def __init__(self, ai_engine: Any = None) -> None:
        self.ai_engine = ai_engine

    # ── Executive Summary ─────────────────────────────────────────────────────

    async def write_executive_summary(self, session: Session) -> str:
        """AI-generated executive summary for board/executive audience."""
        findings = session.db_session.query(FindingModel).filter_by(
            session_id=session.id, verified="unverified"
        ).all()
        all_findings = session.db_session.query(FindingModel).filter_by(
            session_id=session.id
        ).all()

        by_sev: dict[str, int] = {}
        by_owasp: dict[str, int] = {}
        for f in all_findings:
            sev = str(f.severity or "info")
            by_sev[sev] = by_sev.get(sev, 0) + 1
            owasp = str(f.owasp_category or "Other")
            by_owasp[owasp] = by_owasp.get(owasp, 0) + 1

        critical_count = by_sev.get("critical", 0)
        high_count = by_sev.get("high", 0)
        total = len(all_findings)
        fp_count = sum(1 for f in all_findings if f.verified == "false_positive")
        true_positives = total - fp_count

        top_findings = "\n".join(
            f"- [{f.severity.upper()}] {f.title} at {f.target}"
            for f in all_findings
            if str(f.severity) in ("critical", "high") and f.verified != "false_positive"
        )[:2000]

        if self.ai_engine:
            user_prompt = f"""Security Assessment Executive Summary

Engagement: {session.model.name}
Operator: {session.model.operator}
Date: {datetime.now(timezone.utc).strftime('%B %d, %Y')}
Target: {session.model.target}

Total findings: {total} ({fp_count} false positives removed by AI triage)
Confirmed findings: {true_positives}
Critical: {critical_count}, High: {high_count}

Top critical/high findings:
{top_findings if top_findings else 'None'}

OWASP categories most affected:
{chr(10).join(f'- {k}: {v}' for k, v in sorted(by_owasp.items(), key=lambda x: -x[1])[:5])}

Write an executive summary. Emphasize business risk and ROI of remediation."""
            try:
                result = await self.ai_engine.complete(
                    system=EXECUTIVE_PROMPT,
                    user=user_prompt,
                    max_tokens=800,
                )
                if result and isinstance(result, str):
                    return result
            except Exception as exc:
                logger.warning("AI executive summary failed: %s", exc)

        # Fallback template
        return self._fallback_executive_summary(
            session, total, true_positives, fp_count,
            critical_count, high_count, by_sev, by_owasp
        )

    def _fallback_executive_summary(
        self,
        session: Session,
        total: int,
        true_positives: int,
        fp_count: int,
        critical: int,
        high: int,
        by_sev: dict[str, int],
        by_owasp: dict[str, int],
    ) -> str:
        date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")
        owasp_lines = "\n".join(
            f"  • {k} — {v} finding(s)"
            for k, v in sorted(by_owasp.items(), key=lambda x: -x[1])[:5]
        )
        return f"""EXECUTIVE SUMMARY
Security Assessment — {session.model.name}
Date: {date_str} | Operator: {session.model.operator}

OVERVIEW
This security assessment of {session.model.target} identified {true_positives} confirmed
vulnerabilities ({fp_count} scanner false positives removed by AI triage). The findings
represent real risks to the confidentiality, integrity, and availability of the application.

RISK OVERVIEW
  Critical: {critical}   High: {high}   Medium: {by_sev.get('medium', 0)}
  Low: {by_sev.get('low', 0)}   Informational: {by_sev.get('info', 0)}

{"⚠️  IMMEDIATE ACTION REQUIRED: " + str(critical) + " critical vulnerabilities require urgent remediation." if critical else "No critical vulnerabilities identified."}

OWASP TOP 10 COVERAGE
{owasp_lines or "  No OWASP categories mapped."}

RECOMMENDATIONS
  1. Schedule a dedicated remediation sprint for all critical and high findings.
  2. Implement a secure code review process and SAST tools in the CI/CD pipeline.
  3. Re-scan after remediation to verify fixes. Consider a penetration test on critical components.
  4. Establish a vulnerability disclosure policy and bug bounty program.
  5. Ensure security headers, HTTPS enforcement, and dependency updates are maintained.

This report was generated by Medusa Security Framework.
"""

    # ── Technical Narrative ───────────────────────────────────────────────────

    async def write_technical_narrative(
        self, finding: FindingModel, analysis: FindingAnalysis | None
    ) -> str:
        """AI-generated technical narrative for a single finding."""
        if analysis and self.ai_engine:
            user_prompt = f"""Finding: {finding.title}
Severity: {finding.severity}
Target: {finding.target}
Module: {finding.module}
Description: {finding.description}
Payload: {(finding.payload or '')[:500]}
Request: {(finding.request or '')[:500]}
Response: {(finding.response or '')[:500]}
CVSS Score: {analysis.cvss_score} ({analysis.cvss_vector})
OWASP: {analysis.owasp_category}
CWE: {', '.join(analysis.cwe_ids)}
Remediation: {chr(10).join(analysis.remediation_steps[:3])}

Write a technical narrative for this finding."""
            try:
                result = await self.ai_engine.complete(
                    system=TECHNICAL_PROMPT,
                    user=user_prompt,
                    max_tokens=600,
                )
                if result and isinstance(result, str):
                    return result
            except Exception as exc:
                logger.warning("AI technical narrative failed: %s", exc)

        # Fallback
        if analysis:
            return f"""{finding.title}
{'=' * len(str(finding.title))}
Severity: {finding.severity.upper()} | CVSS: {analysis.cvss_score}
Target: {finding.target}
OWASP: {analysis.owasp_category}
CWE: {', '.join(analysis.cwe_ids) if analysis.cwe_ids else 'N/A'}

DESCRIPTION
{finding.description}

TECHNICAL DETAIL
{analysis.technical_explanation}

BUSINESS IMPACT
{analysis.business_impact}

REMEDIATION
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(analysis.remediation_steps))}

REFERENCES
{chr(10).join(analysis.references) if analysis.references else 'See OWASP Top 10 and CWE database.'}
"""
        return f"{finding.title}\nSeverity: {finding.severity}\nTarget: {finding.target}\n\n{finding.description}"

    # ── SARIF Export ──────────────────────────────────────────────────────────

    def to_sarif(self, session: Session) -> dict[str, Any]:
        """Export findings as SARIF 2.1.0 for GitHub Security / IDE integration."""
        findings = session.db_session.query(FindingModel).filter_by(
            session_id=session.id
        ).all()

        rules: dict[str, Any] = {}
        results = []

        for f in findings:
            rule_id = str(f.module).replace(".", "_") + "_" + str(f.title or "finding").replace(" ", "_")[:30]
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": str(f.title),
                    "shortDescription": {"text": str(f.title)},
                    "fullDescription": {"text": str(f.description or f.title)},
                    "defaultConfiguration": {
                        "level": {
                            "critical": "error",
                            "high": "error",
                            "medium": "warning",
                            "low": "note",
                            "info": "none",
                        }.get(str(f.severity), "warning")
                    },
                    "properties": {
                        "tags": list(f.tags or []),
                        "precision": "medium",
                        "severity": str(f.severity),
                    },
                }

            results.append({
                "ruleId": rule_id,
                "level": {
                    "critical": "error",
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "info": "none",
                }.get(str(f.severity), "warning"),
                "message": {"text": str(f.description or f.title)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(f.target)},
                    }
                }],
                "properties": {
                    "module": str(f.module),
                    "payload": str(f.payload or ""),
                    "owasp": str(f.owasp_category or ""),
                    "cwe": list(f.cwe_ids or []),
                },
            })

        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Medusa",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/medusa-security/medusa",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }

    # ── Jira Export ───────────────────────────────────────────────────────────

    def to_jira_issues(self, session: Session) -> list[dict[str, Any]]:
        """Export findings as Jira issue payloads."""
        findings = session.db_session.query(FindingModel).filter_by(
            session_id=session.id
        ).filter(FindingModel.verified != "false_positive").all()

        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }
        issues = []
        for f in findings:
            issues.append({
                "fields": {
                    "summary": f"[Security] {f.title} @ {f.target}",
                    "description": (
                        f"*Severity:* {f.severity.upper()}\n"
                        f"*Target:* {f.target}\n"
                        f"*Module:* {f.module}\n"
                        f"*OWASP:* {f.owasp_category or 'N/A'}\n"
                        f"*CWE:* {', '.join(f.cwe_ids or []) or 'N/A'}\n\n"
                        f"*Description:*\n{f.description}\n\n"
                        f"*Payload:*\n{{code}}{f.payload or 'N/A'}{{/code}}\n\n"
                        f"*Remediation:*\n{f.ai_remediation or 'See security team recommendations.'}"
                    ),
                    "priority": {"name": priority_map.get(str(f.severity), "Medium")},
                    "labels": ["security", "medusa"] + [t for t in (f.tags or []) if len(t) < 50],
                    "issuetype": {"name": "Bug"},
                }
            })
        return issues

    # ── OWASP Coverage Report ─────────────────────────────────────────────────

    def owasp_coverage_report(self, session: Session) -> dict[str, Any]:
        """Generate OWASP Top 10 2021 coverage matrix."""
        owasp_categories = [
            "A01:2021-Broken Access Control",
            "A02:2021-Cryptographic Failures",
            "A03:2021-Injection",
            "A04:2021-Insecure Design",
            "A05:2021-Security Misconfiguration",
            "A06:2021-Vulnerable and Outdated Components",
            "A07:2021-Identification and Authentication Failures",
            "A08:2021-Software and Data Integrity Failures",
            "A09:2021-Security Logging and Monitoring Failures",
            "A10:2021-SSRF",
        ]
        from medusa.engine.core.models import FindingModel as FM
        findings = session.db_session.query(FM).filter_by(session_id=session.id).all()

        coverage: dict[str, list[dict]] = {cat: [] for cat in owasp_categories}
        for f in findings:
            owasp = str(f.owasp_category or "")
            for cat in owasp_categories:
                if cat in owasp or any(
                    part in owasp for part in cat.split("-")[1:]
                ):
                    coverage[cat].append({
                        "id": str(f.id),
                        "title": str(f.title),
                        "severity": str(f.severity),
                        "target": str(f.target),
                    })
                    break

        return {
            "total_findings": len(findings),
            "categories_affected": sum(1 for v in coverage.values() if v),
            "coverage": {
                cat: {
                    "finding_count": len(items),
                    "findings": items,
                    "tested": True,
                }
                for cat, items in coverage.items()
            },
        }


# ── Backward-compat functions ─────────────────────────────────────────────────

async def write_executive_summary(session: Session, ai_engine: Any = None) -> str:
    writer = ReportWriter(ai_engine=ai_engine)
    return await writer.write_executive_summary(session)


async def write_technical_narrative(
    finding: Any, analysis: FindingAnalysis, ai_engine: Any = None
) -> str:
    writer = ReportWriter(ai_engine=ai_engine)
    return await writer.write_technical_narrative(finding, analysis)
