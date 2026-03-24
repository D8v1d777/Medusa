"""
Attack chain builder — TIER 3.
AI-synthesized multi-step attack paths from findings.
Maps to MITRE ATT&CK. Surfaces exploitable sequences analysts miss.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from medusa.engine.core.models import FindingModel
from medusa.engine.core.session import Session

__all__ = ["suggest_chains", "AttackChain", "ChainStep", "ChainBuilder"]

logger = logging.getLogger(__name__)

CHAIN_SYSTEM_PROMPT = """You are an offensive security expert who synthesizes attack chains.
Given a set of vulnerability findings, you identify realistic multi-step attack paths
an attacker could take to achieve high-impact objectives (data exfiltration, full compromise, privilege escalation).
Be realistic. A chain must actually be exploitable. Do not invent steps not supported by the findings.
Output valid JSON only."""


class ChainStepModel(BaseModel):
    finding_id: str
    title: str
    action: str
    outcome: str
    technique: str = ""


class AttackChainModel(BaseModel):
    name: str
    objective: str
    mitre_techniques: list[str]
    steps: list[ChainStepModel]
    likelihood: float = Field(ge=0.0, le=1.0)
    impact: str
    prerequisites: list[str] = Field(default_factory=list)
    notes: str = ""


class AttackChainsOutput(BaseModel):
    chains: list[AttackChainModel] = Field(default_factory=list)
    summary: str = ""


@dataclass
class ChainStep:
    finding_id: str
    action: str
    outcome: str
    technique: str = ""
    title: str = ""


@dataclass
class AttackChain:
    name: str
    mitre_techniques: list[str]
    steps: list[ChainStep]
    likelihood: float
    impact: str
    objective: str = ""
    prerequisites: list[str] = field(default_factory=list)
    notes: str = ""


# ── Rule-based chain patterns (no AI) ────────────────────────────────────────

_CHAIN_PATTERNS: list[dict] = [
    {
        "name": "SQL Injection to Data Exfiltration",
        "requires_tags": {"sqli"},
        "optional_tags": {"error-based", "union-based", "blind", "time-based"},
        "mitre": ["T1190", "T1005"],
        "objective": "Exfiltrate database contents",
        "impact": "Critical — Full database compromise",
        "likelihood": 0.85,
    },
    {
        "name": "XSS to Session Hijacking",
        "requires_tags": {"xss"},
        "optional_tags": {"stored", "reflected", "dom"},
        "mitre": ["T1059.007", "T1185"],
        "objective": "Hijack authenticated user sessions",
        "impact": "High — Account takeover of any victim who views the payload",
        "likelihood": 0.75,
    },
    {
        "name": "SSRF to Internal Network Access",
        "requires_tags": {"ssrf"},
        "optional_tags": {"cloud-metadata", "internal"},
        "mitre": ["T1090", "T1552.005"],
        "objective": "Access internal services and cloud metadata",
        "impact": "Critical — May expose cloud credentials (IAM roles, access keys)",
        "likelihood": 0.80,
    },
    {
        "name": "SSTI to Remote Code Execution",
        "requires_tags": {"ssti"},
        "optional_tags": {"jinja2", "twig", "freemarker"},
        "mitre": ["T1059", "T1190"],
        "objective": "Execute arbitrary commands on the server",
        "impact": "Critical — Full server compromise",
        "likelihood": 0.90,
    },
    {
        "name": "Auth Bypass to Privilege Escalation",
        "requires_tags": {"auth-bypass"},
        "optional_tags": {"jwt", "session", "oauth"},
        "mitre": ["T1078", "T1548"],
        "objective": "Access privileged functionality without valid credentials",
        "impact": "Critical — Administrative access",
        "likelihood": 0.90,
    },
    {
        "name": "BOLA to Horizontal Privilege Escalation",
        "requires_tags": {"bola", "idor"},
        "optional_tags": {"api"},
        "mitre": ["T1078", "T1083"],
        "objective": "Access other users' data",
        "impact": "High — Mass data exposure of all users",
        "likelihood": 0.85,
    },
    {
        "name": "XXE to Local File Read + SSRF",
        "requires_tags": {"xxe"},
        "optional_tags": {"ssrf"},
        "mitre": ["T1190", "T1005", "T1090"],
        "objective": "Read sensitive files and pivot to internal network",
        "impact": "Critical — File system access and internal network pivot",
        "likelihood": 0.80,
    },
    {
        "name": "Default Credentials to Admin Access",
        "requires_tags": {"default-credentials"},
        "optional_tags": {"exposed-panels"},
        "mitre": ["T1078.001", "T1078"],
        "objective": "Authenticate as administrator with default credentials",
        "impact": "Critical — Full administrative access",
        "likelihood": 0.95,
    },
    {
        "name": "Exposed Git Repository to Source Code Disclosure",
        "requires_tags": {"git-exposure", "exposure"},
        "optional_tags": {"sensitive-data"},
        "mitre": ["T1190", "T1552"],
        "objective": "Extract source code, secrets, and credentials from exposed .git",
        "impact": "Critical — Source code and secret exposure",
        "likelihood": 0.90,
    },
    {
        "name": "Missing Rate Limiting to Credential Stuffing",
        "requires_tags": {"rate-limit"},
        "optional_tags": {"auth", "brute-force"},
        "mitre": ["T1110.004"],
        "objective": "Brute force or credential stuff authentication endpoints",
        "impact": "High — Account compromise at scale",
        "likelihood": 0.75,
    },
    {
        "name": "Path Traversal to Sensitive File Read",
        "requires_tags": {"path-traversal", "lfi"},
        "optional_tags": {"sensitive-data"},
        "mitre": ["T1083", "T1005"],
        "objective": "Read server-side sensitive files",
        "impact": "High — Config files, credentials, private keys accessible",
        "likelihood": 0.85,
    },
]


def _find_chains_rule_based(findings: list[FindingModel]) -> list[AttackChain]:
    """Rule-based chain detection from MITRE-backed patterns."""
    all_tags: set[str] = set()
    tag_to_findings: dict[str, list[FindingModel]] = {}

    for f in findings:
        for tag in (f.tags or []):
            all_tags.add(tag.lower())
            if tag.lower() not in tag_to_findings:
                tag_to_findings[tag.lower()] = []
            tag_to_findings[tag.lower()].append(f)

    chains: list[AttackChain] = []
    for pattern in _CHAIN_PATTERNS:
        requires = pattern["requires_tags"]
        if not requires.intersection(all_tags):
            continue

        # Collect relevant findings
        relevant: list[FindingModel] = []
        for tag in requires.union(pattern["optional_tags"]):
            relevant.extend(tag_to_findings.get(tag, []))
        relevant = list({f.id: f for f in relevant}.values())  # deduplicate

        if not relevant:
            continue

        steps = []
        for i, f in enumerate(relevant[:5]):
            steps.append(ChainStep(
                finding_id=str(f.id),
                title=str(f.title),
                action=f"Exploit {f.title} at {f.target}",
                outcome=f"Step {i + 1} — {f.severity.upper()} impact",
                technique=str(pattern["mitre"][0]) if pattern["mitre"] else "",
            ))

        chains.append(AttackChain(
            name=pattern["name"],
            objective=pattern["objective"],
            mitre_techniques=list(pattern["mitre"]),
            steps=steps,
            likelihood=pattern["likelihood"],
            impact=pattern["impact"],
        ))

    return chains


class ChainBuilder:
    """AI-powered attack chain synthesis."""

    def __init__(self, ai_engine: Any = None) -> None:
        self.ai_engine = ai_engine

    async def build(self, findings: list[FindingModel], session: Session) -> list[AttackChain]:
        """Synthesize attack chains from findings."""
        if not findings:
            return []

        high_impact = [f for f in findings if str(f.severity) in ("critical", "high")]
        if not high_impact:
            high_impact = findings[:10]

        # Try AI first
        if self.ai_engine:
            chains = await self._ai_chains(high_impact, session)
            if chains:
                return chains

        # Fallback to rule-based
        return _find_chains_rule_based(high_impact)

    async def _ai_chains(
        self, findings: list[FindingModel], session: Session
    ) -> list[AttackChain]:
        findings_summary = "\n".join(
            f"- [{f.severity.upper()}] {f.title} @ {f.target} (tags: {', '.join(f.tags or [])})"
            for f in findings[:20]
        )
        user_prompt = f"""Findings from security scan of {session.model.name}:

{findings_summary}

Identify realistic multi-step attack chains. For each chain:
- Name it descriptively
- Define the objective
- List 2-5 steps (each tied to a specific finding)
- Assign MITRE ATT&CK techniques
- Rate likelihood (0.0-1.0) and impact

Output AttackChainsOutput JSON."""

        try:
            result = await self.ai_engine.complete(
                system=CHAIN_SYSTEM_PROMPT,
                user=user_prompt,
                schema=AttackChainsOutput,
                max_tokens=2000,
            )
            if isinstance(result, AttackChainsOutput) and result.chains:
                chains = []
                for c in result.chains:
                    steps = [
                        ChainStep(
                            finding_id=s.finding_id,
                            title=s.title,
                            action=s.action,
                            outcome=s.outcome,
                            technique=s.technique,
                        )
                        for s in c.steps
                    ]
                    chains.append(AttackChain(
                        name=c.name,
                        objective=c.objective,
                        mitre_techniques=c.mitre_techniques,
                        steps=steps,
                        likelihood=c.likelihood,
                        impact=c.impact,
                        prerequisites=c.prerequisites,
                        notes=c.notes,
                    ))
                return chains
        except Exception as exc:
            logger.warning("AI chain builder failed: %s", exc)
        return []


# ── Backward compat ───────────────────────────────────────────────────────────

async def suggest_chains(session: Session, ai_engine: Any = None) -> list[AttackChain]:
    """Synthesize attack chains from all session findings."""
    findings = session.db_session.query(FindingModel).filter_by(
        session_id=session.id
    ).all()
    builder = ChainBuilder(ai_engine=ai_engine)
    return await builder.build(findings, session)
