"""Active Directory — Kerberoasting, AS-REP, DCSync, Certipy, BloodHound."""
from __future__ import annotations

import logging

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["ActiveDirAttacks"]

logger = logging.getLogger(__name__)


class ActiveDirAttacks:
    """AD attack chains. Requires domain credentials."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(
        self, domain: str, dc_ip: str, credentials: dict, session: Session
    ) -> None:
        """Run Kerberoasting, AS-REP, etc."""
        pass
