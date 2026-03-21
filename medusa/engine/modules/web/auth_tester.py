"""Auth tester — JWT, session, OAuth, etc."""
from __future__ import annotations

import logging

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["AuthTester"]

logger = logging.getLogger(__name__)


class AuthTester:
    """Authentication and authorization testing."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(self, target: str, session: Session) -> None:
        """Run auth tests."""
        self.guard.check(target, "web.auth_tester")
        async with self.bucket:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                try:
                    resp = await client.get(target)
                    if "Set-Cookie" in resp.headers:
                        session.add_finding(
                            module="web.auth_tester",
                            target=target,
                            title="Session cookie detected",
                            description="Session management uses cookies. Manual JWT/session testing recommended.",
                            severity="info",
                            tags=["auth", "session"],
                        )
                except Exception as e:
                    logger.debug("Auth test %s: %s", target, e)
