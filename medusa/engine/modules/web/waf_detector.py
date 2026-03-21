"""WAF detector — fingerprint WAF before active scanning."""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["WAFDetector", "WAFProfile"]

logger = logging.getLogger(__name__)


@dataclass
class WAFProfile:
    """WAF detection result."""

    vendor: str | None
    confidence: float
    bypass_hints: list[str]


class WAFDetector:
    """Fingerprint WAF presence."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket
        self._probe_payloads = [
            "<script>alert(1)</script>",
            "' OR 1=1--",
        ]

    async def run(self, target: str, session: Session) -> WAFProfile:
        """Detect WAF and return profile."""
        self.guard.check(target, "web.waf_detector")
        vendor = None
        confidence = 0.0
        bypass_hints: list[str] = []

        async with self.bucket:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                try:
                    _normal = await client.get(target)
                    probe = await client.get(
                        target,
                        params={"q": self._probe_payloads[0]},
                    )
                    if probe.status_code == 403:
                        if "cloudflare" in (probe.text or "").lower():
                            vendor = "cloudflare"
                            confidence = 0.8
                            bypass_hints = ["Case variation", "Comment injection"]
                        elif "modsecurity" in (probe.text or "").lower() or "mod_security" in str(probe.headers).lower():
                            vendor = "modsecurity"
                            confidence = 0.7
                            bypass_hints = ["Parameter pollution", "Chunked encoding"]
                except Exception as e:
                    logger.debug("WAF detect %s: %s", target, e)

        return WAFProfile(vendor=vendor, confidence=confidence, bypass_hints=bypass_hints)
