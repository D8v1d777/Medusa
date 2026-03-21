from __future__ import annotations
import httpx
import logging
from typing import List, Literal
from pentkit.core.session import Session
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import TokenBucket

logger = get_module_logger("web.header_analyzer")

class HeaderAnalyzer:
    """Analyzes security headers of a web target."""
    
    def __init__(self, bucket: TokenBucket):
        self.bucket = bucket
        self.headers_to_check = {
            "Content-Security-Policy": ("Missing CSP", "medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
            "Strict-Transport-Security": ("Missing HSTS", "low", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "X-Frame-Options": ("Missing X-Frame-Options (Clickjacking)", "medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
            "X-Content-Type-Options": ("Missing X-Content-Type-Options (MIME Sniffing)", "low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
            "Referrer-Policy": ("Missing Referrer-Policy", "low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "Permissions-Policy": ("Missing Permissions-Policy", "low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        }

    async def run(self, target: str, session: Session):
        """Perform passive header analysis."""
        logger.info(f"Analyzing headers for {target}", extra={"target": target})
        
        async with self.bucket:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                try:
                    response = await client.get(target)
                except Exception as e:
                    logger.error(f"Failed to fetch {target}: {e}", extra={"target": target})
                    return

        # Check for missing headers
        for header, (name, severity, cvss) in self.headers_to_check.items():
            if header not in response.headers:
                session.add_finding(
                    module="web.header_analyzer",
                    target=target,
                    title=name,
                    description=f"The security header '{header}' is missing from the server response.",
                    severity=severity,
                    cvss_vector=cvss,
                    tags=["headers", "passive"]
                )

        # Check for weak CORS
        cors_origin = response.headers.get("Access-Control-Allow-Origin")
        if cors_origin == "*":
            session.add_finding(
                module="web.header_analyzer",
                target=target,
                title="Wildcard CORS Policy",
                description="The 'Access-Control-Allow-Origin' header is set to '*', allowing any domain to access resources.",
                severity="medium",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                tags=["headers", "cors"]
            )

__all__ = ["HeaderAnalyzer"]
