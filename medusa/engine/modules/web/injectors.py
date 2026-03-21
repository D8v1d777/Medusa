"""Injection engine — SQLi, XSS, SSRF, etc."""
from __future__ import annotations

import logging
from pathlib import Path

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.modules.web.crawler import SiteMap

__all__ = ["Injectors"]

logger = logging.getLogger(__name__)


class Injectors:
    """Injection testing engine."""

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        payload_dir: Path | None = None,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.payload_dir = payload_dir or Path(__file__).parent.parent.parent / "payloads" / "web"

    async def run(self, sitemap: SiteMap, session: Session) -> None:
        """Run injection tests on sitemap endpoints and forms."""
        sqli_payloads = ["' OR '1'='1", "1' OR '1'='1' --", "1; SELECT SLEEP(5)--"]
        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            for url in sitemap.endpoints[:20]:
                self.guard.check(url, "web.injectors")
                for payload in sqli_payloads[:1] + xss_payloads[:1]:
                    async with self.bucket:
                        try:
                            resp = await client.get(url, params={"q": payload})
                            is_sqli = any(
                                e in (resp.text or "").lower()
                                for e in ["sql", "syntax", "mysql", "ora-", "postgres"]
                            )
                            is_xss_reflected = payload in (resp.text or "")
                            if is_sqli:
                                session.add_finding(
                                    module="web.injectors",
                                    target=url,
                                    title="Potential SQL Injection",
                                    description=f"Error-based SQLi. Payload: {payload}",
                                    severity="high",
                                    payload=payload,
                                    request=f"GET {url}?q={payload}",
                                    response=resp.text[:2000] if resp.text else "",
                                    tags=["sqli", "error-based"],
                                )
                            elif is_xss_reflected:
                                session.add_finding(
                                    module="web.injectors",
                                    target=url,
                                    title="Potential Reflected XSS",
                                    description=f"Payload reflected unescaped. Payload: {payload}",
                                    severity="medium",
                                    payload=payload,
                                    request=f"GET {url}?q={payload}",
                                    response=resp.text[:2000] if resp.text else "",
                                    tags=["xss", "reflected"],
                                )
                        except Exception as e:
                            logger.debug("Inject test %s: %s", url, e)
