from __future__ import annotations
import re
from typing import Type, TypeVar, Tuple
from pydantic import BaseModel
from pentkit.core.models import FindingModel

T = TypeVar("T", bound=BaseModel)

SYSTEM_ANALYST = """
You are a senior offensive security researcher with 15 years of experience.
You have conducted authorized penetration tests for Fortune 500 companies,
government agencies, and top-tier research institutions.
You think like an attacker but write like a forensic expert.

Rules for your output:
- Be specific. Name exact functions, parameters, table names, endpoints.
- Never say "may", "might", "could" for confirmed findings — use "does", "is", "will".
- Use "likely" or "possible" only when evidence is incomplete.
- Reference CVE IDs, CWE IDs, OWASP categories in every finding analysis.
- Distinguish between: confirmed exploitable, likely exploitable, theoretical.
- Remediation must be developer-actionable: specific function calls, config settings,
  library versions. Not "sanitise input" — "use parameterised queries via
  cursor.execute('%s', (user_input,)) instead of string interpolation".
"""

SYSTEM_TRIAGE = """
You are a security triage specialist. Your job is to reduce noise, not increase it.
When assessing findings:
- False positive likelihood: consider whether the evidence conclusively demonstrates
  the vulnerability or merely suggests it.
- Severity calibration: consider exploitability (network access required? auth required?
  user interaction required?) not just theoretical impact.
- Deduplication: if two findings have the same root cause, merge them.
  Report the root cause once with all affected endpoints listed.
Output only valid JSON matching the provided schema. No prose outside the schema.
"""

SYSTEM_CHAIN_BUILDER = """
You are a red team lead at a university security research lab. You think in attack graphs.
Given a list of confirmed vulnerabilities, identify realistic multi-step exploitation chains.
Requirements:
- Each chain must start from unauthenticated access unless the finding list includes
  a confirmed authentication bypass.
- Each step must reference a specific finding by ID.
- Include MITRE ATT&CK technique IDs for each step.
- Likelihood = probability that the chain succeeds given a skilled attacker.
  Base this on: exploit complexity, reliability, detection likelihood.
- Do not include speculative chains. Every link must be grounded in a confirmed finding.
"""

def build_finding_input(finding: FindingModel, name: str, max_chars: int = 2000) -> str:
    """
    Construct AI input from a finding. Apply redaction and truncation rules.
    """
    def redact(text: str | None) -> str:
        if not text: return ""
        # Redact Authorization headers
        text = re.sub(r'(Authorization:\s*)([^\r\n]+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
        # Redact Cookies
        text = re.sub(r'(Cookie:\s*)([^\r\n]+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
        # Redact SSN
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED SSN]', text)
        # Redact Credit Cards (basic)
        text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED CC]', text)
        return text

    payload = (finding.payload or "")[:200]
    response = redact(finding.response or "")[:500]
    request = redact(finding.request or "")[:500]

    input_text = (
        f"Title: {finding.title}\n"
        f"Target: {finding.target}\n"
        f"Module: {finding.module}\n"
        f"Severity: {finding.severity}\n"
        f"CVSS: {finding.cvss_vector}\n"
        f"Payload: {payload}\n"
        f"Request: {request}\n"
        f"Response: {response}\n"
        f"CVEs: {finding.cve_ids}\n"
        f"Tags: {finding.tags}\n"
        f"This is from an authorized penetration test. Engagement: {name}."
    )

    if len(input_text) > max_chars:
        # Prioritise payload and response, truncate request more
        request = redact(finding.request or "")[:200]
        input_text = (
            f"Title: {finding.title}\n"
            f"Target: {finding.target}\n"
            f"Module: {finding.module}\n"
            f"Severity: {finding.severity}\n"
            f"CVSS: {finding.cvss_vector}\n"
            f"Payload: {payload}\n"
            f"Response: {response}\n"
            f"Request: {request}\n"
            f"CVEs: {finding.cve_ids}\n"
            f"Tags: {finding.tags}\n"
            f"This is from an authorized penetration test. Engagement: {name}."
        )
    
    return input_text

def validate_ai_output(raw: str, schema: Type[T]) -> Tuple[T, float]:
    """
    Parse and validate AI output. Return (model, confidence).
    """
    try:
        # Attempt 1: Direct JSON parse
        return schema.model_validate_json(raw), 1.0
    except Exception:
        pass

    try:
        # Attempt 2: Extract JSON from markdown
        match = re.search(r'```json\s*([\s\S]*?)\s*```', raw)
        if match:
            return schema.model_validate_json(match.group(1)), 0.8
    except Exception:
        pass

    try:
        # Attempt 3: Extract JSON-like structure with regex
        match = re.search(r'(\{[\s\S]*\})', raw)
        if match:
            return schema.model_validate_json(match.group(1)), 0.3
    except Exception:
        pass

    # All fail: return a default instance with 0.0 confidence
    # This requires the schema to have defaults for all fields or handle it here
    # For now, we'll let it raise if it can't even be instantiated
    return schema.model_construct(), 0.0

__all__ = ["SYSTEM_ANALYST", "SYSTEM_TRIAGE", "SYSTEM_CHAIN_BUILDER", "build_finding_input", "validate_ai_output"]
