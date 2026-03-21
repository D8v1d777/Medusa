"""API fuzzer — OpenAPI discovery, type confusion, BOLA."""
from __future__ import annotations

import logging

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["APIFuzzer"]

logger = logging.getLogger(__name__)

API_SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/v1/docs",
    "/openapi.yaml",
]


class APIFuzzer:
    """API discovery and fuzzing."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(self, target: str, session: Session) -> None:
        """Discover and fuzz API endpoints."""
        base = target.rstrip("/")
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            for path in API_SPEC_PATHS:
                self.guard.check(base + path, "web.api_fuzzer")
                async with self.bucket:
                    try:
                        resp = await client.get(base + path)
                        if resp.status_code == 200:
                            session.add_finding(
                                module="web.api_fuzzer",
                                target=base + path,
                                title="API specification exposed",
                                description=f"OpenAPI/Swagger spec found at {path}",
                                severity="low",
                                tags=["api", "discovery"],
                            )
                    except Exception:
                        pass
