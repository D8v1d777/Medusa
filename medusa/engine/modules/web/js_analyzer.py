"""JS analyzer — secrets, endpoints, debug flags."""
from __future__ import annotations

import logging
import re

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.modules.web.crawler import SiteMap

__all__ = ["JSAnalyzer"]

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (r"api[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API key"),
    (r"aws_secret[_\w]*\s*[:=]\s*['\"]([a-zA-Z0-9/+=]{40})['\"]", "AWS secret"),
]


class JSAnalyzer:
    """JavaScript file analyzer for secrets and endpoints."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(
        self, sitemap: SiteMap, session: Session
    ) -> None:
        """Analyze JS files for secrets."""
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            for js_url in sitemap.js_files[:10]:
                self.guard.check(js_url, "web.js_analyzer")
                async with self.bucket:
                    try:
                        resp = await client.get(js_url)
                        for pattern, name in SECRET_PATTERNS:
                            for m in re.finditer(pattern, resp.text or "", re.I):
                                session.add_finding(
                                    module="web.js_analyzer",
                                    target=js_url,
                                    title=f"Potential {name} in JS",
                                    description=f"Possible secret match in {js_url}",
                                    severity="high",
                                    confidence="low",
                                    tags=["js", "secret", "recon"],
                                )
                    except Exception as e:
                        logger.debug("JS analyze %s: %s", js_url, e)
