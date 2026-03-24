"""
AI Triage — TIER 3.
False positive reduction using LLM.
The most professionally impactful feature in Medusa.
Target: < 8% false positive rate (vs ZAP's ~40%, Nuclei's ~15%).
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from medusa.engine.core.models import FindingModel
from medusa.engine.core.session import Session

__all__ = ["AITriage", "FindingAssessment", "triage"]

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """You are a Principal Security Researcher at a top-tier cybersecurity firm.
Your task is to TRIAGE vulnerability findings from an automated scanner (Medusa).
Goal: Minimize false positives while maintaining a conservative security posture.

CRITICAL INSTRUCTIONS:
1. THINK STEP-BY-STEP (Chain of Thought):
   - Analyze the target URL and context (is it a public API? a static site? a login page?).
   - Examine the Request: Did the scanner send a valid payload for the claimed vulnerability?
   - Examine the Response: Look for status codes, headers (CSP, WAF), and body content.
   - Contrast Request vs Response: Is there a clear causal link (e.g., payload reflected, timing difference)?

2. FALSE POSITIVE INDICATORS (is_false_positive: true):
   - WAF INTERFERENCE: Response is a standard Cloudflare/Akamai block page (403/406).
   - GENERIC ERRORS: A generic 500 error that occurs for any invalid input, not just the exploit.
   - NON-EXECUTABLE REFLECTION: Payload reflected inside a non-JS context (e.g., metadata tag) with safe headers.
   - PATH TRAVERSAL NOISE: "/etc/passwd" appearing as part of a help page or example text.
   - SSRF NOISE: Requests to 127.0.0.1 that are handled by a local proxy but don't reach internal services.

3. TRUE POSITIVE INDICATORS (is_false_positive: false):
   - DATA EXFILTRATION: Response contains actual sensitive data (hashes, keys, PII).
   - OOB CALLBACK: Finding includes evidence of an out-of-band interaction (DNS/HTTP).
   - SOURCE CODE LEAK: Response contains clear markers of source code (<?php, import statement).
   - BROKEN ACCESS: Accessing /admin or /config without a valid session (302/200).

4. SEVERITY ADJUSTMENT (CVSS 3.1 Logic):
   - Adjust based on: Scope (S), Impact (C, I, A), and Exploitability (AV, AC, PR, UI).
   - If UI interaction is required (e.g. CSRF/XSS): Severity usually <= Medium/High.
   - If PR (Privileges Required) is 'High': Downgrade one level.
   - If credentials/tokens are found: Always 'Critical'.

Output valid JSON only."""


class FindingAssessment(BaseModel):
    """AI triage result for a single finding."""
    is_false_positive: bool = Field(description="True if this is a false positive")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in assessment 0-1")
    adjusted_severity: str = Field(description="critical/high/medium/low/info")
    reasoning: str = Field(description="Brief reasoning for the assessment")
    remediation: str = Field(description="Developer-ready fix recommendation")
    triage_notes: str = Field(default="", description="Additional triage analyst notes")


@dataclass
class TriageResult:
    """Full triage result."""
    finding_id: str
    assessment: FindingAssessment
    original_severity: str


async def _triage_one(
    finding: FindingModel,
    ai_engine: Any,
    session: Session,
) -> TriageResult | None:
    """Triage a single finding with AI."""
    user_prompt = f"""Finding to assess:
Template/Module: {finding.module}
Title: {finding.title}
Severity: {finding.severity}
Target: {finding.target}
Description: {finding.description}
Payload: {(finding.payload or '')[:500]}
Request: {(finding.request or '')[:800]}
Response: {(finding.response or '')[:1000]}
CVE IDs: {json.dumps(finding.cve_ids or [])}
Tags: {json.dumps(finding.tags or [])}

Assess this finding and output FindingAssessment JSON."""

    try:
        result = await ai_engine.complete(
            system=TRIAGE_SYSTEM_PROMPT,
            user=user_prompt,
            schema=FindingAssessment,
            max_tokens=600,
        )
        if isinstance(result, FindingAssessment):
            return TriageResult(
                finding_id=str(finding.id),
                assessment=result,
                original_severity=str(finding.severity),
            )
    except Exception as exc:
        logger.warning("AI triage failed for finding %s: %s", finding.id, exc)
    return None


async def _apply_triage_result(
    finding: FindingModel, result: TriageResult, session: Session
) -> None:
    """Apply triage assessment back to the finding in the DB."""
    fa = result.assessment
    finding.ai_explanation = fa.reasoning
    finding.ai_remediation = fa.remediation
    finding.confidence = "low" if fa.is_false_positive else (
        "high" if fa.confidence > 0.8 else "medium"
    )
    finding.verified = "false_positive" if fa.is_false_positive else "unverified"

    # Apply severity adjustment
    valid_severities = {"critical", "high", "medium", "low", "info"}
    if fa.adjusted_severity in valid_severities:
        finding.severity = fa.adjusted_severity

    try:
        session.db_session.commit()
    except Exception as exc:
        logger.error("DB commit error during triage: %s", exc)


class AITriage:
    """
    AI-powered false positive reduction.
    Runs on all findings after each module completes.
    """

    def __init__(self, ai_engine: Any = None) -> None:
        self.ai_engine = ai_engine

    async def run(
        self,
        findings: list[FindingModel],
        session: Session,
        concurrency: int = 5,
    ) -> list[TriageResult]:
        """
        Triage all findings for a session.
        Runs in parallel batches of `concurrency`.
        """
        if not findings:
            return []

        engine = self.ai_engine
        if engine is None:
            try:
                from medusa.engine.core.ai_engine import AIEngine
                from medusa.engine.core.config import AIConfig
                ai_cfg = AIConfig()
                engine = AIEngine(ai_cfg)
            except Exception:
                logger.warning("AI engine unavailable — using rule-based triage")
                return await self._rule_based_triage(findings, session)

        results: list[TriageResult] = []
        semaphore = asyncio.Semaphore(concurrency)

        async def _bounded(finding: FindingModel) -> TriageResult | None:
            async with semaphore:
                return await _triage_one(finding, engine, session)

        tasks = [_bounded(f) for f in findings]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for finding, result in zip(findings, raw_results):
            if isinstance(result, TriageResult):
                await _apply_triage_result(finding, result, session)
                results.append(result)

        fp_count = sum(1 for r in results if r.assessment.is_false_positive)
        logger.info(
            "AI triage complete: %d findings, %d false positives removed",
            len(findings), fp_count,
        )
        return results

    async def _rule_based_triage(
        self, findings: list[FindingModel], session: Session
    ) -> list[TriageResult]:
        """Fallback rule-based triage when AI is unavailable."""
        results = []
        seen: dict[tuple[str, str], bool] = {}

        for f in findings:
            key = (str(f.target), str(f.title))
            is_dup = key in seen
            seen[key] = True

            assessment = FindingAssessment(
                is_false_positive=is_dup,
                confidence=0.6 if is_dup else 0.75,
                adjusted_severity=str(f.severity),
                reasoning="Duplicate finding removed by rule-based deduplication." if is_dup else "Rule-based: no AI available.",
                remediation="Review and fix the identified vulnerability.",
                triage_notes="Rule-based triage — AI not available",
            )
            result = TriageResult(
                finding_id=str(f.id),
                assessment=assessment,
                original_severity=str(f.severity),
            )
            await _apply_triage_result(f, result, session)
            results.append(result)
        return results


# ── Backward compat ───────────────────────────────────────────────────────────

async def triage(
    findings: list[FindingModel], session: Session
) -> list[FindingModel]:
    """
    Deduplication and severity-adjustment using AI triage.
    Backward-compatible entry point.
    """
    t = AITriage()
    await t.run(findings, session)
    # Return only non-false-positive findings
    return [f for f in findings if f.verified != "false_positive"]
