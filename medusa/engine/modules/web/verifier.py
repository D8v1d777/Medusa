"""Finding verifier — confirm findings before report."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from medusa.engine.core.models import FindingModel
from medusa.engine.core.session import Session

__all__ = ["FindingVerifier", "VerificationResult"]

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Verification result."""

    verified: bool | None
    reason: str
    evidence: str | None = None


class FindingVerifier:
    """Verifies findings before reporting."""

    async def verify(
        self, finding: FindingModel, session: Session
    ) -> VerificationResult:
        """Verify a single finding."""
        return VerificationResult(verified=None, reason="no_verifier_for_type")

    async def run_verification_pass(
        self, findings: list[FindingModel], session: Session
    ) -> list[FindingModel]:
        """Run verification on high/critical findings."""
        return findings
