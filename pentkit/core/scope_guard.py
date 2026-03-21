from __future__ import annotations
import ipaddress
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Optional

logger = logging.getLogger(__name__)

class OutOfScopeError(Exception):
    """Raised when a target is not within the authorized scope."""
    def __init__(self, target: str, module: str = "unknown"):
        self.target = target
        self.module = module
        super().__init__(f"Out of scope attempt: target={target}, module={module}")

class ScopeGuard:
    """Whitelist enforcement for authorized pentesting targets."""
    
    def __init__(self, ips: list[str], domains: list[str], cidrs: list[str]):
        """
        Initialize the guard with whitelisted targets.
        
        :param ips: List of exact IP addresses.
        :param domains: List of domains and subdomains.
        :param cidrs: List of network ranges (e.g., 192.168.1.0/24).
        """
        self.ips = [ipaddress.ip_address(ip) for ip in ips]
        self.domains = [d.lower() for d in domains]
        self.networks = [ipaddress.ip_network(n) for n in cidrs]

    def _get_hostname(self, target: str) -> str:
        """Extract hostname from a URL or return the target if it's already a hostname/IP."""
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                return parsed.netloc.split(':')[0].lower()
            return target.lower()
        except Exception:
            return target.lower()

    def is_safe(self, target: str) -> bool:
        """
        Return True if target is in scope, False otherwise.
        Batch pre-filtering version that does not raise.
        """
        hostname = self._get_hostname(target)

        # 1. Check direct IP match
        try:
            target_ip = ipaddress.ip_address(hostname)
            if target_ip in self.ips:
                return True
            # 2. Check CIDR match
            if any(target_ip in network for network in self.networks):
                return True
        except ValueError:
            # Not an IP, check domain
            pass

        # 3. Check Domain match (exact + subdomains)
        for domain in self.domains:
            if hostname == domain or hostname.endswith("." + domain):
                return True

        return False

    def check(self, target: str, module: str = "unknown") -> None:
        """
        Raise OutOfScopeError if target is not in whitelist.
        Logs every attempt (success or failure).
        """
        in_scope = self.is_safe(target)
        
        # Log the attempt
        log_entry = {
            "ts": datetime.now().isoformat(),
            "target": target,
            "module": module,
            "in_scope": in_scope
        }
        
        if not in_scope:
            logger.warning("Scope violation: %s", log_entry)
            raise OutOfScopeError(target, module)
        
        logger.debug("Scope check passed: %s", log_entry)

__all__ = ["OutOfScopeError", "ScopeGuard"]
