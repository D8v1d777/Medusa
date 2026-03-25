"""Advanced detection engine — real-time network and web assessment."""
import logging
import asyncio
import socket
import ssl
import struct
from typing import List, Any, Dict
from medusa.engine.core.session import Session
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.rate_limiter import TokenBucket

logger = logging.getLogger(__name__)

BLOCKLIST_URL = "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"

# Banner fingerprint database for service identification
BANNER_FINGERPRINTS = {
    b"SSH-": ("SSH", "Remote access service"),
    b"220 ": ("FTP/SMTP", "File transfer or mail relay"),
    b"HTTP/": ("HTTP", "Web server"),
    b"* OK ": ("IMAP", "Mail box protocol"),
    b"+OK ": ("POP3", "Mail retrieval"),
    b"MySQL": ("MySQL", "Database server"),
    b"\x00\x00\x00": ("MySQL/Binary", "Database protocol handshake"),
    b"Redis": ("Redis", "In-memory data store"),
    b"-ERR": ("Redis", "Redis error response"),
    b"MongoDB": ("MongoDB", "Document database"),
    b"\x15\x03": ("TLS Alert", "TLS/SSL service"),
    b"\\x00\\x00": ("SMB", "Windows file sharing"),
}

# Service risk classification
RISK_MATRIX = {
    21: {"name": "FTP", "risk": "high", "note": "Cleartext authentication. Credentials transmitted without encryption."},
    22: {"name": "SSH", "risk": "info", "note": "Encrypted shell access. Check for weak ciphers and key exchange algorithms."},
    23: {"name": "Telnet", "risk": "critical", "note": "Unencrypted remote access. Full credential interception possible."},
    25: {"name": "SMTP", "risk": "medium", "note": "Mail relay. Check for open relay configuration (SPF/DKIM bypass)."},
    53: {"name": "DNS", "risk": "medium", "note": "DNS resolver. Zone transfer (AXFR) and cache poisoning vectors."},
    80: {"name": "HTTP", "risk": "info", "note": "Web server. Further analysis via web assessment modules."},
    110: {"name": "POP3", "risk": "medium", "note": "Cleartext mail retrieval. Credential sniffing possible."},
    139: {"name": "NetBIOS-SS", "risk": "critical", "note": "NetBIOS Session Service. SMB relay and null session enumeration."},
    443: {"name": "HTTPS", "risk": "info", "note": "Encrypted web. Certificate and TLS configuration analysis required."},
    445: {"name": "SMB", "risk": "critical", "note": "Server Message Block. EternalBlue (MS17-010), PrintNightmare, PetitPotam vectors."},
    1433: {"name": "MSSQL", "risk": "high", "note": "Microsoft SQL Server. xp_cmdshell, SQL injection escalation path."},
    1521: {"name": "Oracle", "risk": "high", "note": "Oracle DB listener. TNS poisoning and authentication bypass vectors."},
    3306: {"name": "MySQL", "risk": "high", "note": "MySQL database exposed. UDF injection and privilege escalation paths."},
    3389: {"name": "RDP", "risk": "high", "note": "Remote Desktop. BlueKeep (CVE-2019-0708), NLA bypass, brute force vectors."},
    5432: {"name": "PostgreSQL", "risk": "high", "note": "PostgreSQL exposed. COPY FROM PROGRAM RCE vector."},
    5900: {"name": "VNC", "risk": "high", "note": "Virtual Network Computing. Authentication bypass, screen capture."},
    6379: {"name": "Redis", "risk": "critical", "note": "Redis unauth. CONFIG SET dir/dbfilename for arbitrary file write → RCE."},
    8080: {"name": "HTTP-Alt", "risk": "medium", "note": "Alternative HTTP. Often admin panels, development servers."},
    8443: {"name": "HTTPS-Alt", "risk": "medium", "note": "Alternative HTTPS. Management interfaces."},
    9200: {"name": "Elasticsearch", "risk": "critical", "note": "Elasticsearch REST API. Index enumeration, data exfiltration, RCE via script."},
    27017: {"name": "MongoDB", "risk": "critical", "note": "MongoDB exposed. Default no-auth. Full database dump possible."},
    # ICS/SCADA
    102: {"name": "S7comm", "risk": "critical", "note": "Siemens S7 PLC protocol. Industrial control system — potential physical impact."},
    502: {"name": "Modbus", "risk": "critical", "note": "Modbus TCP — no authentication by design. SCADA register read/write."},
    20000: {"name": "DNP3", "risk": "critical", "note": "Distributed Network Protocol. Grid/power infrastructure."},
    47808: {"name": "BACnet", "risk": "critical", "note": "Building automation. HVAC, access control manipulation."},
}


class SovereignScanner:
    """Real-time threat detection and assessment engine."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket):
        self.guard = guard
        self.bucket = bucket

    async def fetch_blocked_ips(self) -> List[str]:
        """Fetch real-time malicious IPs from threat intelligence feeds."""
        logger.info("[*] Syncing threat intelligence feed...")
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(BLOCKLIST_URL) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        ips = [line.strip() for line in content.splitlines() if line and not line.startswith("#")]
                        logger.info(f"  [{len(ips)} threat actors loaded from Feodo Tracker]")
                        return ips[:50]
        except Exception as e:
            logger.error(f"[!] Intelligence sync failed: {e}")
        return []

    async def _probe_port(self, target: str, port: int) -> Dict[str, Any]:
        """Asynchronous port probe with service banner extraction."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=3)
            banner = ""
            service_id = "unknown"
            
            try:
                # Send probe data for services that need it
                if port in (80, 8080, 8443):
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                    await writer.drain()
                elif port == 6379:
                    writer.write(b"PING\r\n")
                    await writer.drain()
                elif port == 27017:
                    # MongoDB wire protocol ismaster command
                    writer.write(b'\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x15\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00')
                    await writer.drain()
                
                banner_bytes = await asyncio.wait_for(reader.read(2048), timeout=2)
                banner = banner_bytes.decode(errors="replace").strip()
                
                # Fingerprint the service
                for sig, (svc_name, desc) in BANNER_FINGERPRINTS.items():
                    if banner_bytes.startswith(sig) or sig in banner_bytes[:64]:
                        service_id = svc_name
                        break
                        
            except Exception:
                pass
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            return {"port": port, "open": True, "banner": banner, "service": service_id}
        except Exception:
            return {"port": port, "open": False}

    async def _check_ssl(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration for weaknesses."""
        result = {"has_ssl": False}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ctx), timeout=5
            )
            
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                result["has_ssl"] = True
                result["version"] = ssl_obj.version()
                result["cipher"] = ssl_obj.cipher()
                
                cert = ssl_obj.getpeercert(binary_form=True)
                if cert:
                    # Decode cert info
                    peer_cert = ssl_obj.getpeercert()
                    if peer_cert:
                        result["subject"] = dict(x[0] for x in peer_cert.get("subject", ()))
                        result["issuer"] = dict(x[0] for x in peer_cert.get("issuer", ()))
                        result["expires"] = peer_cert.get("notAfter")
                        result["serial"] = peer_cert.get("serialNumber")
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
                
        except Exception as e:
            result["error"] = str(e)[:100]
        
        return result

    async def scan_network(self, target: str) -> List[Dict[str, Any]]:
        """Perform deep port scan with service fingerprinting."""
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 502, 1433, 1521, 
                 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
        
        tasks = [self._probe_port(target, p) for p in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r["open"]]

    async def run_expert_flags(self, target: str, session: Session):
        """Deep, real-world assessment pipeline."""
        logger.info(f"  Analyzing: {target}")

        # ── 1. Network Scan ──
        open_ports = await self.scan_network(target)
        
        for pinfo in open_ports:
            port = pinfo["port"]
            banner = pinfo.get("banner", "")
            detected_svc = pinfo.get("service", "unknown")
            
            risk_data = RISK_MATRIX.get(port, {"name": detected_svc, "risk": "info", "note": "Service detected."})
            svc_name = risk_data["name"]
            risk_level = risk_data["risk"]
            risk_note = risk_data["note"]
            
            # Build description with real intelligence
            desc_parts = [f"Verified open port {port}/tcp on {target}."]
            desc_parts.append(f"Service: {svc_name}")
            if banner:
                # Clean banner for display (limit length, strip control chars)
                clean_banner = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' for c in banner[:500])
                desc_parts.append(f"Banner:\n{clean_banner}")
            desc_parts.append(f"\nAssessment: {risk_note}")
            
            # Add specific exploit references for critical services
            if port == 445:
                desc_parts.append("\nKnown exploits: MS17-010 (EternalBlue), CVE-2020-0796 (SMBGhost), PrintNightmare")
            elif port == 3389:
                desc_parts.append("\nKnown exploits: CVE-2019-0708 (BlueKeep), CVE-2019-1181/1182 (DejaBlue)")
            elif port == 6379:
                desc_parts.append("\nExploitation: CONFIG SET dir /var/spool/cron → Crontab write → reverse shell")
            elif port == 9200:
                desc_parts.append("\nExploitation: /_cat/indices → data enum, /_search → full dump, _scripts → RCE")
            elif port == 27017:
                desc_parts.append("\nExploitation: db.adminCommand({listDatabases:1}) → full database enumeration")
            
            session.add_finding(
                module="redteam.sovereign",
                target=f"{target}:{port}",
                title=f"Active Service: {port}/tcp ({svc_name})",
                description="\n".join(desc_parts),
                severity=risk_level,
                tags=["live-detection", "network", "port-scan"]
            )

        # ── 2. SSL/TLS Analysis (if 443 open) ──
        ssl_ports = [r["port"] for r in open_ports if r["port"] in (443, 8443)]
        for ssl_port in ssl_ports:
            ssl_info = await self._check_ssl(target, ssl_port)
            if ssl_info.get("has_ssl"):
                cipher_info = ssl_info.get("cipher", ())
                cipher_name = cipher_info[0] if cipher_info else "unknown"
                tls_version = ssl_info.get("version", "unknown")
                
                issues = []
                sev = "info"
                
                if "TLSv1.0" in str(tls_version) or "TLSv1.1" in str(tls_version):
                    issues.append(f"Deprecated TLS version: {tls_version}")
                    sev = "high"
                if "RC4" in cipher_name or "DES" in cipher_name or "NULL" in cipher_name:
                    issues.append(f"Weak cipher: {cipher_name}")
                    sev = "high"
                if "CBC" in cipher_name:
                    issues.append(f"CBC mode cipher (BEAST/POODLE vector): {cipher_name}")
                    if sev == "info":
                        sev = "medium"
                
                subject = ssl_info.get("subject", {})
                issuer = ssl_info.get("issuer", {})
                
                desc = f"TLS/SSL Analysis for {target}:{ssl_port}\n"
                desc += f"Protocol: {tls_version}\n"
                desc += f"Cipher: {cipher_name}\n"
                if subject:
                    desc += f"Subject CN: {subject.get('commonName', 'N/A')}\n"
                if issuer:
                    desc += f"Issuer: {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}\n"
                desc += f"Expires: {ssl_info.get('expires', 'N/A')}\n"
                if issues:
                    desc += f"\nISSUES DETECTED:\n" + "\n".join(f"  • {i}" for i in issues)
                
                session.add_finding(
                    module="redteam.tls",
                    target=f"{target}:{ssl_port}",
                    title=f"TLS Configuration: {tls_version} / {cipher_name[:30]}",
                    description=desc,
                    severity=sev,
                    tags=["live-detection", "tls", "crypto"]
                )

        # ── 3. Web Fuzzing (if HTTP ports open) ──
        web_ports = [r["port"] for r in open_ports if r["port"] in (80, 443, 8080, 8443)]
        if web_ports:
            try:
                import aiohttp
                timeout = aiohttp.ClientTimeout(total=5)
                
                for wp in web_ports:
                    proto = "https" if wp in (443, 8443) else "http"
                    base_url = f"{proto}://{target}" if wp in (80, 443) else f"{proto}://{target}:{wp}"
                    
                    sensitive_paths = [
                        ("/.env", "critical", "Environment variables — may contain database credentials, API keys"),
                        ("/.git/config", "critical", "Git repository metadata — source code exposure"),
                        ("/.git/HEAD", "critical", "Git ref pointer — confirms source code deployment"),
                        ("/phpinfo.php", "high", "PHP configuration dump — full server info disclosure"),
                        ("/server-status", "high", "Apache status page — request URL leakage"),
                        ("/robots.txt", "info", "Robots exclusion — reveals hidden paths"),
                        ("/sitemap.xml", "info", "Sitemap — full URL enumeration"),
                        ("/.well-known/security.txt", "info", "Security contact info"),
                        ("/wp-login.php", "info", "WordPress detected"),
                        ("/api/v1", "info", "API endpoint enumeration"),
                        ("/config.json", "high", "Application configuration leak"),
                        ("/backup.sql", "critical", "Database backup — full data exposure"),
                        ("/debug", "high", "Debug endpoint — may expose internals"),
                        ("/actuator/health", "medium", "Spring Boot actuator — info disclosure"),
                        ("/swagger-ui.html", "medium", "API documentation — endpoint enumeration"),
                        ("/.DS_Store", "medium", "macOS directory metadata — file listing"),
                    ]

                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as http_session:
                        for path, default_sev, note in sensitive_paths:
                            try:
                                async with http_session.get(f"{base_url}{path}") as resp:
                                    if resp.status == 200:
                                        content = await resp.text()
                                        content_len = len(content)
                                        
                                        # Validate it's not a generic 404 page
                                        if content_len < 20 or "not found" in content.lower()[:200]:
                                            continue
                                        
                                        # Extract snippet for evidence
                                        snippet = content[:300].replace('\n', ' ').strip()
                                        
                                        desc = f"HTTP {resp.status} on {base_url}{path}\n"
                                        desc += f"Content-Length: {content_len} bytes\n"
                                        desc += f"Content-Type: {resp.headers.get('Content-Type', 'unknown')}\n"
                                        desc += f"\nEvidence snippet:\n{snippet}...\n"
                                        desc += f"\nRisk: {note}"
                                        
                                        session.add_finding(
                                            module="redteam.web",
                                            target=f"{base_url}{path}",
                                            title=f"Exposed: {path}",
                                            description=desc,
                                            severity=default_sev,
                                            tags=["live-detection", "web", "exposure"]
                                        )
                            except Exception:
                                pass
            except ImportError:
                logger.warning("  aiohttp not available — skipping web probes")

        total = len(session.findings)
        if total == 0:
            logger.info(f"  No findings confirmed against {target}")
        else:
            logger.info(f"  {total} finding(s) recorded")


async def run_sovereign(guard, bucket, target, session):
    scanner = SovereignScanner(guard, bucket)
    if target == "DISCOVER":
        ips = await scanner.fetch_blocked_ips()
        if ips:
            logger.info(f"  Discovery mode: scanning top 3 from {len(ips)} threat actors")
            for ip in ips[:3]:
                await scanner.run_expert_flags(ip, session)
        else:
            logger.error("  Failed to fetch target list")
    else:
        await scanner.run_expert_flags(target, session)
