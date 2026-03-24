"""
AI Analyst — TIER 3.
Per-finding deep analysis: technical explanation, business impact,
remediation steps, CVSS justification, OWASP category, CWE IDs, references.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from medusa.engine.core.models import FindingModel

__all__ = ["explain", "FindingAnalysis", "DeepAnalysisResult"]

logger = logging.getLogger(__name__)

ANALYST_SYSTEM_PROMPT = """You are a Senior Security Analyst and Technical Writer for a world-class penetration testing firm.
Your task is to provide a COMPLETE and PROFESSIONAL analysis of a security finding.

STRUCTURE YOUR ANALYSIS:
1. TECHNICAL EXPLANATION: Detailed, developer-ready explanation of WHY this is a vulnerability. 
   Mention the specific mechanism (e.g. "lack of context-aware output encoding in the /search route").
2. BUSINESS IMPACT: High-level risk assessment for executives. Use terms like "Data Breach", "Reputational Damage", "Regulatory Non-compliance (GDPR/PCI)".
3. REMEDIATION STEPS: A prioritized list of EXACT fixes. Do not use generic advice; be specific to the technology if detected.
4. CVSS 3.1: Provide the exact vector string (AV, AC, PR, UI, S, C, I, A).
5. OWASP: Map to the 2021 Top 10 category (e.g., A01:2021-Broken Access Control).
6. MITRE ATT&CK: Map to specific techniques (e.g., T1190 Exploit Public-Facing Application).
7. PROOF OF CONCEPT: Provide a clear, step-by-step reproduction guide for the QA team.

Keep the tone professional, objective, and authoritative. Output JSON only."""


class DeepAnalysisResult(BaseModel):
    """Full deep analysis output from AI."""
    technical_explanation: str = Field(description="Technical description of the vulnerability")
    business_impact: str = Field(description="Business risk and impact")
    remediation_steps: list[str] = Field(description="Ordered developer-ready fix steps")
    cvss_vector: str = Field(default="", description="CVSS v3.1 vector string")
    cvss_score: float = Field(default=0.0, description="CVSS v3.1 base score")
    cvss_justification: str = Field(description="Justification for CVSS scoring")
    owasp_category: str = Field(description="OWASP Top 10 2021 category")
    cwe_ids: list[str] = Field(default_factory=list, description="CWE identifiers")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    proof_of_concept: str = Field(default="", description="PoC steps for verification")
    false_positive_indicators: list[str] = Field(default_factory=list)
    true_positive_indicators: list[str] = Field(default_factory=list)


@dataclass
class FindingAnalysis:
    """AI analysis result (backward compat dataclass)."""
    technical_explanation: str
    business_impact: str
    remediation_steps: list[str]
    cvss_justification: str
    owasp_category: str
    cwe_ids: list[str]
    references: list[str]
    cvss_vector: str = ""
    cvss_score: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    proof_of_concept: str = ""


# CVSS/OWASP lookup for fallback
_SEVERITY_CVSS = {
    "critical": (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high":     (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "medium":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low":      (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "info":     (0.0, ""),
}

_TAG_OWASP = {
    "sqli": "A03:2021-Injection",
    "xss": "A03:2021-Injection",
    "ssti": "A03:2021-Injection",
    "xxe": "A03:2021-Injection",
    "ssrf": "A10:2021-SSRF",
    "auth": "A07:2021-Identification and Authentication Failures",
    "jwt": "A07:2021-Identification and Authentication Failures",
    "idor": "A01:2021-Broken Access Control",
    "bola": "A01:2021-Broken Access Control",
    "cors": "A01:2021-Broken Access Control",
    "path-traversal": "A01:2021-Broken Access Control",
    "outdated-library": "A06:2021-Vulnerable and Outdated Components",
    "sensitive-data": "A02:2021-Cryptographic Failures",
    "misconfiguration": "A05:2021-Security Misconfiguration",
    "headers": "A05:2021-Security Misconfiguration",
}

_CWE_MAP = {
    "sqli": ["CWE-89"],
    "xss": ["CWE-79"],
    "ssrf": ["CWE-918"],
    "xxe": ["CWE-611"],
    "ssti": ["CWE-94"],
    "path-traversal": ["CWE-22"],
    "idor": ["CWE-639"],
    "bola": ["CWE-639"],
    "cors": ["CWE-942"],
    "jwt": ["CWE-345"],
    "csrf": ["CWE-352"],
    "nosql": ["CWE-943"],
    "ldap": ["CWE-90"],
}

_MITRE_MAP = {
    "sqli": ["T1190"],
    "xss": ["T1059.007"],
    "ssrf": ["T1090"],
    "xxe": ["T1190"],
    "ssti": ["T1059"],
    "path-traversal": ["T1083"],
    "idor": ["T1083"],
    "bola": ["T1078"],
}

_REMEDIATION_LIBRARY = {
    "sqli": [
        "Use parameterized queries or prepared statements exclusively.",
        "Apply an ORM with built-in query escaping.",
        "Validate and whitelist all user input before use in queries.",
        "Apply principle of least privilege to the DB account.",
        "Enable query logging and anomaly detection.",
    ],
    "xss": [
        "HTML-encode all user-controlled output using a context-aware encoding library.",
        "Implement a strict Content-Security-Policy (CSP) header.",
        "Use framework built-in output encoding (React JSX, Angular template binding).",
        "Set HttpOnly and Secure flags on all session cookies.",
        "Sanitize rich text using DOMPurify or equivalent.",
    ],
    "ssrf": [
        "Deny all outbound requests to internal IP ranges (RFC 1918) by default.",
        "Use an allowlist of permitted destination domains.",
        "Disable unnecessary URL schemes (file://, gopher://, dict://).",
        "Validate parsed URLs after canonicalization to prevent bypass.",
        "Run the application with network-level isolation (VPC, firewall rules).",
    ],
    "ssti": [
        "Never pass user-controlled data to template rendering functions.",
        "Use sandboxed template environments.",
        "Validate all template context variables before rendering.",
        "Update template engine to the latest patched version.",
    ],
    "xxe": [
        "Disable DTD processing in the XML parser: FEATURE_DISALLOW_DOCTYPE_DECL.",
        "Disable external entity resolution.",
        "Use a safe XML library (defusedxml in Python).",
        "Accept only expected XML structures — reject unexpected fields.",
    ],
    "path-traversal": [
        "Resolve paths using realpath() and verify they are within the allowed base directory.",
        "Use a UUID or indirect reference instead of user-supplied filenames.",
        "Deny sequences like ../ and ..\\, and URL-encoded equivalents.",
    ],
    "idor": [
        "Implement per-object authorization checks on every request.",
        "Use indirect object references (UUIDs) instead of sequential integers.",
        "Verify resource ownership server-side before returning data.",
        "Log and alert on rapid sequential ID enumeration.",
    ],
    "cors": [
        "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins.",
        "Never combine Allow-Credentials: true with Allow-Origin: *.",
        "Validate the Origin header server-side against the allowlist.",
        "Set Vary: Origin to prevent caching of CORS responses.",
    ],
    "default": [
        "Review and fix the identified vulnerability.",
        "Test the fix in a staging environment.",
        "Add a regression test to the CI pipeline.",
    ],
}


def _get_remediation(tags: list[str]) -> list[str]:
    for tag in tags:
        if tag in _REMEDIATION_LIBRARY:
            return _REMEDIATION_LIBRARY[tag]
    return _REMEDIATION_LIBRARY["default"]


def _get_owasp(tags: list[str], owasp_field: str) -> str:
    if owasp_field:
        return owasp_field
    for tag in tags:
        if tag in _TAG_OWASP:
            return _TAG_OWASP[tag]
    return "A05:2021-Security Misconfiguration"


def _get_cwes(tags: list[str], existing: list[str]) -> list[str]:
    if existing:
        return existing
    for tag in tags:
        if tag in _CWE_MAP:
            return _CWE_MAP[tag]
    return []


def _get_mitre(tags: list[str]) -> list[str]:
    for tag in tags:
        if tag in _MITRE_MAP:
            return _MITRE_MAP[tag]
    return ["T1190"]


async def explain(
    finding: FindingModel,
    sitemap: object | None,
    session: object,
    ai_engine: Any = None,
) -> FindingAnalysis:
    """
    Generate technical explanation, business impact, remediation, CVSS,
    OWASP category, CWE IDs, and references for a single finding.
    """
    tags = list(finding.tags or [])
    sev = str(finding.severity or "medium")
    cvss_score, cvss_vector = _SEVERITY_CVSS.get(sev, (5.0, ""))
    owasp = _get_owasp(tags, str(finding.owasp_category or ""))
    cwes = _get_cwes(tags, list(finding.cwe_ids or []))
    mitre = _get_mitre(tags)
    remediation = _get_remediation(tags)

    if ai_engine:
        user_prompt = f"""Analyse this security finding:

Module: {finding.module}
Title: {finding.title}
Severity: {sev}
Target: {finding.target}
Description: {finding.description}
Payload: {(finding.payload or '')[:500]}
Request: {(finding.request or '')[:600]}
Response: {(finding.response or '')[:600]}
Tags: {tags}
CVE IDs: {finding.cve_ids}

Output DeepAnalysisResult JSON with:
- technical_explanation (2-3 sentences)
- business_impact (1-2 sentences)
- remediation_steps (3-5 actionable steps for developers)
- cvss_vector (CVSS v3.1 string)
- cvss_score (0-10 float)
- cvss_justification (1 sentence)
- owasp_category
- cwe_ids (list)
- mitre_techniques (list of T-codes)
- references (list of URLs to OWASP, CWE, CVE)
- proof_of_concept (reproduction steps)"""

        try:
            result = await ai_engine.complete(
                system=ANALYST_SYSTEM_PROMPT,
                user=user_prompt,
                schema=DeepAnalysisResult,
                max_tokens=1200,
            )
            if isinstance(result, DeepAnalysisResult):
                # Write back to DB
                finding.ai_explanation = result.technical_explanation
                finding.ai_remediation = "\n".join(result.remediation_steps)
                if result.cvss_score:
                    finding.cvss_score = result.cvss_score
                if result.cvss_vector:
                    finding.cvss_vector = result.cvss_vector
                if result.owasp_category:
                    finding.owasp_category = result.owasp_category
                if result.cwe_ids:
                    finding.cwe_ids = result.cwe_ids
                if result.mitre_techniques:
                    finding.mitre_technique = result.mitre_techniques[0] if result.mitre_techniques else None
                try:
                    session.db_session.commit()  # type: ignore
                except Exception:
                    pass

                return FindingAnalysis(
                    technical_explanation=result.technical_explanation,
                    business_impact=result.business_impact,
                    remediation_steps=result.remediation_steps,
                    cvss_justification=result.cvss_justification,
                    owasp_category=result.owasp_category,
                    cwe_ids=result.cwe_ids,
                    references=result.references,
                    cvss_vector=result.cvss_vector,
                    cvss_score=result.cvss_score,
                    mitre_techniques=result.mitre_techniques,
                    proof_of_concept=result.proof_of_concept,
                )
        except Exception as exc:
            logger.warning("AI analyst failed: %s — using rule-based fallback", exc)

    # Rule-based fallback
    return FindingAnalysis(
        technical_explanation=str(finding.description or ""),
        business_impact=f"A {sev} severity vulnerability at {finding.target} may allow attackers to compromise the confidentiality, integrity, or availability of the application.",
        remediation_steps=remediation,
        cvss_justification=f"Based on standard CVSS v3.1 scoring for {sev}-severity {finding.module} findings.",
        owasp_category=owasp,
        cwe_ids=cwes,
        references=[
            f"https://owasp.org/www-project-top-ten/",
            f"https://cwe.mitre.org/data/definitions/{cwes[0].replace('CWE-', '')}.html" if cwes else "",
        ],
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        mitre_techniques=mitre,
    )
