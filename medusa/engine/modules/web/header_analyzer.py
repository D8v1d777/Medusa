"""Header analyzer — passive security header checks."""
from __future__ import annotations

import logging

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["HeaderAnalyzer"]

logger = logging.getLogger(__name__)

HEADERS_CHECK = {
    "Content-Security-Policy": (
        "Missing CSP",
        "medium",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    "Strict-Transport-Security": (
        "Missing HSTS",
        "low",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "X-Frame-Options": (
        "Missing X-Frame-Options (Clickjacking)",
        "medium",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    ),
    "X-Content-Type-Options": (
        "Missing X-Content-Type-Options (MIME Sniffing)",
        "low",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    ),
}


class HeaderAnalyzer:
    """Analyzes security headers."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(self, target: str, session: Session) -> None:
        """Perform passive header analysis."""
        self.guard.check(target, "web.header_analyzer")
        async with self.bucket:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                try:
                    response = await client.get(target)
                except Exception as e:
                    logger.error("Header analysis failed %s: %s", target, e)
                    return

        for header, (name, severity, cvss) in HEADERS_CHECK.items():
            if header not in response.headers:
                session.add_finding(
                    module="web.header_analyzer",
                    target=target,
                    title=name,
                    description=f"Security header '{header}' is missing.",
                    severity=severity,
                    cvss_vector=cvss,
                    tags=["headers", "passive"],
                )
