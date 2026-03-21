"""MITM — ARP poisoning, credential capture."""
from __future__ import annotations

import logging

from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["MITMOrchestrator"]

logger = logging.getLogger(__name__)


class MITMOrchestrator:
    """Manages MITM strategies. Requires root/admin."""

    def __init__(self, guard: ScopeGuard) -> None:
        self.guard = guard

    async def run(
        self, gateway_ip: str, target_ip: str, session: Session
    ) -> None:
        """Run MITM. Scope check mandatory before any packet."""
        self.guard.check(gateway_ip, "network.mitm")
        self.guard.check(target_ip, "network.mitm")
        logger.info("MITM would run against %s via %s", target_ip, gateway_ip)
        # Full implementation requires scapy, root; placeholder for Phase 3
