"""ORM hunter — raw query escape hatches."""
from __future__ import annotations

import logging

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.modules.web.crawler import SiteMap

__all__ = ["ORMRawQueryHunter"]

logger = logging.getLogger(__name__)


class ORMRawQueryHunter:
    """Targets ORM raw query escape hatches."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(
        self, sitemap: SiteMap, orm: str | None, session: Session
    ) -> None:
        """Search for SQLi in sort/order/export parameters."""
        high_risk_params = ["sort", "order", "orderby", "q", "search", "filter"]
        for url in sitemap.endpoints[:15]:
            if "?" in url:
                continue
            self.guard.check(url, "web.orm_hunter")
            for param in high_risk_params:
                async with self.bucket:
                    pass
