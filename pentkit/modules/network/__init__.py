import asyncio
from typing import List, Optional
from pentkit.core.session import Session, Finding
from pentkit.core.logger import get_module_logger
from pentkit.modules.network.scanner import NetworkScanner
from pentkit.modules.network.proto_testers import SMBTester, SNMPTester, LDAPTester
from pentkit.modules.network.evasion import EvasionEngine

logger = get_module_logger("network")

async def run(target: str, session: Session, evasion: Optional[str] = None) -> List[Finding]:
    """Orchestrate all network module sub-components."""
    logger.info(f"Starting network module scan against {target}", extra={"target": target})
    
    # 1. Scanner (Port scan + OS detection + CVE lookup)
    evasion_engine = EvasionEngine(evasion)
    evasion_flags = evasion_engine.get_nmap_flags()
    
    scanner = NetworkScanner()
    profiles = await scanner.run(target, session, evasion_flags)
    
    # 2. Protocol Testers (For each host and open port)
    smb_tester = SMBTester()
    snmp_tester = SNMPTester()
    ldap_tester = LDAPTester()
    
    for profile in profiles:
        for port_info in profile.ports:
            port = port_info['port']
            if port == 445:
                await smb_tester.run(profile.ip, session)
            elif port == 161:
                await snmp_tester.run(profile.ip, session)
            elif port in [389, 636]:
                await ldap_tester.run(profile.ip, session)

    logger.info(f"Network module scan complete for {target}", extra={"target": target})
    return []
