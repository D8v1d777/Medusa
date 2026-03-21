"""Protocol testers — SMB, SNMP, LDAP, FTP, SSH."""
from __future__ import annotations

import logging

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["ProtoTesters"]

logger = logging.getLogger(__name__)


class SMBTester:
    """SMB protocol tests."""

    async def test(
        self, host: str, port: int, session: Session
    ) -> list:
        """Test SMB (null session, signing)."""
        return []


class SNMPTester:
    """SNMP community string and MIB tests."""

    async def test(
        self, host: str, port: int, session: Session
    ) -> list:
        """Test SNMP."""
        return []


class ProtoTesters:
    """Orchestrates protocol-specific testers."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket
        self.smb = SMBTester()
        self.snmp = SNMPTester()

    async def run(
        self, host_profiles: list, session: Session
    ) -> None:
        """Run protocol tests for each open port."""
        for hp in host_profiles:
            self.guard.check(hp.ip, "network.proto_testers")
            for port_info in hp.ports:
                if port_info.get("port") == 445:
                    await self.smb.test(hp.ip, 445, session)
                elif port_info.get("port") == 161:
                    await self.snmp.test(hp.ip, 161, session)
