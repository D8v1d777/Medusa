import asyncio
import os
from typing import List, Dict, Optional
from pentkit.core.session import Session, Finding
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import rate_limiter
from impacket.smbconnection import SMBConnection
from pysnmp.hlapi.asyncio import *

logger = get_module_logger("network.proto_testers")

class SMBTester:
    async def run(self, target: str, session: Session):
        """Check for null sessions and SMB signing status."""
        logger.info(f"Running SMB test on {target}", extra={"target": target})
        loop = asyncio.get_event_loop()
        try:
            conn = await loop.run_in_executor(None, lambda: SMBConnection(target, target))
            is_signing_required = conn.isSigningRequired()
            if not is_signing_required:
                session.add_finding(Finding(
                    module="network.smb_tester", target=target, severity="MEDIUM",
                    payload="SMB Connection", request="SMB Negotiate",
                    response="Signing Not Required", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    details={"issue": "SMB signing not required (Relay possible)"}
                ))
            
            # Check for null session
            try:
                await loop.run_in_executor(None, lambda: conn.login('', ''))
                session.add_finding(Finding(
                    module="network.smb_tester", target=target, severity="HIGH",
                    payload="NULL Login", request="SMB Login('', '')",
                    response="Success", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    details={"issue": "SMB NULL session allowed"}
                ))
            except Exception:
                pass
            
            conn.logoff()
        except Exception as e:
            logger.debug(f"SMB test failed for {target}: {e}")

class SNMPTester:
    async def run(self, target: str, session: Session):
        """Community string brute (v1/v2c) and enumeration."""
        logger.info(f"Running SNMP test on {target}", extra={"target": target})
        
        # Load communities from payload generator
        from pentkit.payloads.generator import generator as payload_gen
        # Since the generator currently defaults to web dir, I'll pass a different path
        # Actually I'll update the generator to handle multiple directories
        communities = payload_gen.load_payloads("network/snmp")
        if not communities:
            communities = ["public", "private", "manager", "admin"]
            
        snmp_engine = SnmpEngine()
        
        for community in communities:
            auth_data = CommunityData(community, mpModel=1)  # v2c
            transport_target = await UdpTransportTarget.create((target, 161))
            
            error_indication, error_status, error_index, var_binds = await get_cmd(
                snmp_engine,
                auth_data,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )

            if not error_indication and not error_status:
                session.add_finding(Finding(
                    module="network.snmp_tester", target=target, severity="HIGH",
                    payload=community, request=f"SNMP Get sysDescr ({community})",
                    response=str(var_binds[0][1]), cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    details={"issue": f"SNMP community string discovered: {community}"}
                ))
                break

class LDAPTester:
    async def run(self, target: str, session: Session):
        """Anonymous bind attempt."""
        from ldap3 import Server, Connection, ALL
        logger.info(f"Running LDAP test on {target}", extra={"target": target})
        server = Server(target, get_info=ALL)
        try:
            conn = Connection(server, user='', password='')
            if conn.bind():
                session.add_finding(Finding(
                    module="network.ldap_tester", target=target, severity="MEDIUM",
                    payload="Anonymous Bind", request="LDAP Bind('', '')",
                    response="Success", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    details={"issue": "LDAP anonymous bind allowed"}
                ))
                conn.unbind()
        except Exception as e:
            logger.debug(f"LDAP test failed for {target}: {e}")
