"""Port scanner — nmap wrapper."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["NetworkScanner", "HostProfile"]

logger = logging.getLogger(__name__)


@dataclass
class HostProfile:
    """Host scan result."""

    ip: str
    hostname: str | None
    ports: list[dict]
    os_guess: str | None


class NetworkScanner:
    """Nmap-based port scanner."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(
        self, target: str, session: Session
    ) -> list[HostProfile]:
        """Run port scan. Uses asyncio.to_thread for nmap."""
        self.guard.check(target, "network.scanner")
        async with self.bucket:
            try:
                result = await asyncio.to_thread(
                    self._run_nmap, target
                )
                return result
            except Exception as e:
                logger.error("Scan failed %s: %s", target, e)
                return []

    def _run_nmap(self, target: str) -> list[HostProfile]:
        """Blocking nmap run."""
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments="-sV -T4 -F")
            results = []
            for host in nm.all_hosts():
                ports = []
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        ports.append({
                            "port": port,
                            "state": nm[host][proto][port]["state"],
                            "service": nm[host][proto][port].get("name", ""),
                        })
                results.append(HostProfile(
                    ip=host,
                    hostname=nm[host].hostname() or None,
                    ports=ports,
                    os_guess=None,
                ))
            return results
        except ImportError:
            return [HostProfile(ip=target.split("/")[0], hostname=None, ports=[], os_guess=None)]
