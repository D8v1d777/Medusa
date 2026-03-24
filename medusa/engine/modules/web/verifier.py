"""
Finding Verifier — TIER 2.
Automated rule-based verification of findings before AI triage.
Ensures evidence exists in the response and filters out common scanner noise.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx
from medusa.engine.core.models import FindingModel
from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster

__all__ = ["FindingVerifier", "VerificationResult"]

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Detailed verification outcome."""
    verified: bool  # True (confirmed), False (false positive), None (uncertain)
    reason: str
    evidence: str | None = None


class FindingVerifier:
    """
    Orchestrates automated verification of findings.
    Reduces the workload for the AI Triage module.
    """

    def __init__(self, broadcaster: WSBroadcaster | None = None) -> None:
        self.broadcaster = broadcaster or WSBroadcaster()

    async def run_pass(self, findings: list[FindingModel], session: Session) -> list[FindingModel]:
        """Perform recursive verification on high/critical findings."""
        await self.broadcaster.log(session.id, "INFO", f"[verifier] Verifying {len(findings)} findings", "web.verifier")
        
        verified_count = 0
        fp_count = 0

        for finding in findings:
            result = await self.verify(finding, session)
            
            if result.verified is True:
                finding.verified = "true_positive"
                finding.verification_note = result.reason
                verified_count += 1
            elif result.verified is False:
                finding.verified = "false_positive"
                finding.verification_note = result.reason
                fp_count += 1
            else:
                finding.verified = "unverified"
        
        await self.broadcaster.log(
            session.id, "INFO",
            f"[verifier] Done. {verified_count} confirmed, {fp_count} false positives removed.",
            "web.verifier"
        )
        return findings

    async def verify(self, finding: FindingModel, session: Session) -> VerificationResult:
        """
        Verify a single finding based on its type and evidence.
        """
        module = finding.module or ""
        
        # ── Group 1: Injection (XSS, SQLi, SSTI) ───────────────────────────
        if any(x in module for x in ("xss", "sqli", "ssti", "injectors")):
            return await self._verify_injection(finding)

        # ── Group 2: Sensitive Files / Leaks ──────────────────────────────
        if any(x in module for x in ("template_engine", "env_leak", "js_analyzer")):
            return self._verify_leaks(finding)

        # ── Group 3: Headers ───────────────────────────────────────────────
        if "header" in module:
            return VerificationResult(verified=True, reason="header_rule_passive")

        return VerificationResult(verified=True, reason="no_specific_verifier")

    async def _verify_injection(self, finding: FindingModel) -> VerificationResult:
        """Confirms if the payload reflection or behavior is present in the response."""
        resp = finding.response or ""
        payload = finding.payload or ""

        if not resp:
            return VerificationResult(verified=False, reason="missing_response_body")

        # 1. Reflection Check (XSS)
        if "xss" in str(finding.title).lower():
            if payload in resp:
                return VerificationResult(verified=True, reason="payload_reflection_confirmed", evidence=payload)
            return VerificationResult(verified=False, reason="payload_not_reflected")

        # 2. SQLi Error Check
        db_errors = [
            "SQL syntax", "mysql_fetch", "ORA-01756", "sqlite3.Error", "PostgreSQL query failed",
            "PDOException", "Dynamic SQL Error", "Server Error in '/' Application"
        ]
        if any(err.lower() in resp.lower() for err in db_errors):
            return VerificationResult(verified=True, reason="db_error_confirmed")

        # 3. Path Traversal Check
        if "traversal" in str(finding.title).lower():
            if any(x in resp for x in ("root:x:0:0:", "[extensions]", "boot loader")):
                return VerificationResult(verified=True, reason="os_file_content_leaked")
            return VerificationResult(verified=False, reason="traversal_pattern_not_found")

        return VerificationResult(True, "injected_presumed_active")

    def _verify_leaks(self, finding: FindingModel) -> VerificationResult:
        """Verify sensitive data exposure findings."""
        resp = finding.response or ""
        title = str(finding.title).lower()

        if "env" in title or "config" in title:
            # Check for common env markers
            if any(x in resp for x in ("DB_", "AWS_", "SECRET", "APP_ENV")):
                return VerificationResult(verified=True, reason="confirmed_env_markers")
            return VerificationResult(verified=False, reason="spurious_env_file_hit")

        if "secret" in title or "key" in title:
            # Basic entropy check (triage will do better)
            if len(re.findall(r"[a-fA-F0-9]{32,}", resp)) > 0 or len(re.findall(r"sk-[a-zA-Z0-9]{20,}", resp)) > 0:
                return VerificationResult(verified=True, reason="entropy_confirmed")

        return VerificationResult(True, "leak_presumed_valid")
