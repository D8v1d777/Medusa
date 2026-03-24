"""
Network scanner — TIER 4 (20% focus).
Nmap wrapper with CVE correlation, OS detection, version detection.
Covers Nessus Essentials scope: port scanning, CVE correlation, service enumeration.
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster

__all__ = ["NetworkScanner", "HostProfile", "PortInfo"]

logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    """Single port scan result."""
    port: int
    protocol: str
    state: str
    service: str
    version: str
    product: str
    cpe: str = ""
    cves: list[dict] = field(default_factory=list)


@dataclass
class HostProfile:
    """Full host scan result."""
    ip: str
    hostname: str | None
    ports: list[PortInfo]
    os_guess: str | None
    os_accuracy: int = 0
    mac_address: str | None = None
    vendor: str | None = None
    scan_time: float = 0.0


def _parse_nmap_xml(xml_text: str) -> list[HostProfile]:
    """Parse nmap XML output into HostProfile objects."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
    except Exception as exc:
        logger.error("Nmap XML parse error: %s", exc)
        return []

    profiles: list[HostProfile] = []
    for host_el in root.findall(".//host"):
        # IP
        ip = ""
        hostname = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                pass  # handled below

        # Hostname
        for hn in host_el.findall(".//hostname"):
            hostname = hn.get("name")
            break

        # OS
        os_guess = None
        os_accuracy = 0
        for osm in host_el.findall(".//osmatch"):
            os_guess = osm.get("name")
            os_accuracy = int(osm.get("accuracy", 0))
            break

        # Ports
        ports: list[PortInfo] = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port_el.find("service") or ET.Element("service")
            cpes = [c.text or "" for c in port_el.findall(".//cpe")]

            ports.append(PortInfo(
                port=int(port_el.get("portid", 0)),
                protocol=port_el.get("protocol", "tcp"),
                state=state_el.get("state", ""),
                service=svc.get("name", ""),
                version=svc.get("version", ""),
                product=svc.get("product", ""),
                cpe=cpes[0] if cpes else "",
            ))

        profiles.append(HostProfile(
            ip=ip,
            hostname=hostname,
            ports=ports,
            os_guess=os_guess,
            os_accuracy=os_accuracy,
        ))
    return profiles


class NetworkScanner:
    """
    Nmap-based port scanner with CVE correlation.
    Covers: SYN scan, top-1000 ports, OS detection, version detection.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        broadcaster: WSBroadcaster | None = None,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.broadcaster = broadcaster or WSBroadcaster()

    async def run(self, target: str, session: Session) -> list[HostProfile]:
        """
        Run port scan. Returns HostProfile list.
        Uses nmap for the actual scan, with CVE correlation per service.
        """
        self.guard.check(target, "network.scanner")
        await self.broadcaster.log(
            session.id, "INFO", f"[network.scanner] Scanning {target}", "network.scanner"
        )
        await self.broadcaster.emit_progress(session.id, "network.scanner", 0, "running")

        nmap_path = shutil.which("nmap")
        if not nmap_path:
            logger.warning("nmap not found — using python-nmap fallback")
            return await asyncio.to_thread(self._run_python_nmap, target, session)

        profiles = await self._run_nmap_subprocess(target, nmap_path, session)
        if not profiles:
            return []

        # CVE correlation for each open port
        await self._correlate_cves(profiles, session)

        # Create findings for open ports
        await self._create_port_findings(profiles, session)

        await self.broadcaster.emit_progress(session.id, "network.scanner", 100, "done")
        await self.broadcaster.log(
            session.id, "SUCCESS",
            f"[network.scanner] Found {sum(len(h.ports) for h in profiles)} open ports across {len(profiles)} host(s)",
            "network.scanner",
        )
        return profiles

    async def _run_nmap_subprocess(
        self, target: str, nmap_path: str, session: Session
    ) -> list[HostProfile]:
        """Run nmap as subprocess and parse XML output."""
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            xml_out = tf.name

        cmd = [
            nmap_path,
            "-sV",           # version detection
            "-O",            # OS detection
            "--top-ports", "1000",
            "-T4",           # aggressive timing
            "-oX", xml_out,  # XML output
            "--script", "banner,http-title,ssh-hostkey",
            target,
        ]
        try:
            await self.broadcaster.log(session.id, "INFO",
                                       f"[nmap] Running: {' '.join(cmd[:-1])} {target}", "network.scanner")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            if stderr:
                logger.debug("nmap stderr: %s", stderr.decode(errors="ignore")[:500])

            import os as _os
            xml_text = open(xml_out, encoding="utf-8", errors="ignore").read()
            profiles = _parse_nmap_xml(xml_text)
            return profiles
        except asyncio.TimeoutError:
            logger.error("nmap timed out on %s", target)
            return []
        except Exception as exc:
            logger.error("nmap error: %s", exc)
            return []
        finally:
            try:
                os.unlink(xml_out)
            except Exception:
                pass

    def _run_python_nmap(self, target: str, session: Session) -> list[HostProfile]:
        """Fallback to python-nmap library."""
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments="-sV -T4 --top-ports 1000 -O")
            results: list[HostProfile] = []
            for host in nm.all_hosts():
                ports: list[PortInfo] = []
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        svc = nm[host][proto][port]
                        ports.append(PortInfo(
                            port=port,
                            protocol=proto,
                            state=svc.get("state", ""),
                            service=svc.get("name", ""),
                            version=svc.get("version", ""),
                            product=svc.get("product", ""),
                            cpe=svc.get("cpe", ""),
                        ))
                os_match = nm[host].get("osmatch", [])
                os_guess = os_match[0].get("name") if os_match else None
                results.append(HostProfile(
                    ip=host,
                    hostname=nm[host].hostname() or None,
                    ports=ports,
                    os_guess=os_guess,
                ))
            return results
        except ImportError:
            logger.error("python-nmap not installed")
            return []
        except Exception as exc:
            logger.error("python-nmap error: %s", exc)
            return []

    async def _correlate_cves(self, profiles: list[HostProfile], session: Session) -> None:
        """Correlate open services with CVEs via NVD API."""
        from medusa.engine.modules.network.cve_correlator import CVECorrelator
        correlator = CVECorrelator()

        for host in profiles:
            for port in host.ports:
                if not port.product and not port.service:
                    continue
                try:
                    cves = await correlator.lookup(
                        cpe=port.cpe if port.cpe else None,
                        product=port.product or port.service,
                        version=port.version,
                    )
                    port.cves = [
                        {
                            "cve_id": c.cve_id,
                            "cvss_score": c.cvss_score,
                            "has_exploit": c.has_exploit,
                            "exploit_url": c.exploit_url,
                        }
                        for c in cves
                    ]
                    if cves:
                        top = max(cves, key=lambda c: c.cvss_score)
                        sev = "critical" if top.cvss_score >= 9 else (
                            "high" if top.cvss_score >= 7 else (
                            "medium" if top.cvss_score >= 4 else "low"
                        ))
                        session.add_finding(
                            module="network.cve_correlator",
                            target=f"{host.ip}:{port.port}",
                            title=f"Vulnerable Service: {port.product or port.service} {port.version}",
                            description=(
                                f"Service {port.product} {port.version} on {host.ip}:{port.port}/{port.protocol} "
                                f"has {len(cves)} known CVEs. Top CVSS: {top.cvss_score} ({top.cve_id})."
                            ),
                            severity=sev,  # type: ignore
                            cve_ids=[c.cve_id for c in cves[:5]],
                            tags=["network", "cve", port.service],
                            owasp_category="A06:2021-Vulnerable and Outdated Components",
                            details={
                                "cves": [c.cve_id for c in cves],
                                "cvss_scores": {c.cve_id: c.cvss_score for c in cves},
                            },
                        )
                except Exception as exc:
                    logger.debug("CVE correlation error for %s:%d: %s", host.ip, port.port, exc)

    async def _create_port_findings(
        self, profiles: list[HostProfile], session: Session
    ) -> None:
        """Create findings for interesting open ports."""
        RISKY_SERVICES = {
            21: ("FTP", "medium", "FTP is unencrypted — consider SFTP"),
            23: ("Telnet", "high", "Telnet transmits data in plaintext"),
            69: ("TFTP", "medium", "TFTP has no authentication"),
            110: ("POP3", "low", "Unencrypted POP3 in use"),
            143: ("IMAP", "low", "Unencrypted IMAP in use"),
            512: ("rexec", "high", "Remote execution service exposed"),
            513: ("rlogin", "high", "Remote login service exposed"),
            514: ("rsh", "high", "Remote shell exposed"),
            873: ("rsync", "medium", "rsync may expose sensitive files"),
            1433: ("MSSQL", "medium", "Database port exposed to network"),
            1521: ("Oracle DB", "medium", "Database port exposed to network"),
            3306: ("MySQL", "medium", "Database port exposed to network"),
            3389: ("RDP", "medium", "RDP exposed — brute-force risk"),
            4444: ("nc/metasploit", "high", "Suspicious port — possible backdoor"),
            5432: ("PostgreSQL", "medium", "Database port exposed to network"),
            5900: ("VNC", "high", "VNC exposed — remote access risk"),
            6379: ("Redis", "high", "Redis exposed without auth — data at risk"),
            7001: ("WebLogic", "high", "Java application server exposed"),
            8080: ("HTTP-Alt", "info", "HTTP alternative port"),
            8443: ("HTTPS-Alt", "info", "HTTPS alternative port"),
            9200: ("Elasticsearch", "high", "Elasticsearch exposed — data disclosure risk"),
            27017: ("MongoDB", "high", "MongoDB exposed — may have no auth"),
        }

        for host in profiles:
            for port in host.ports:
                if port.port in RISKY_SERVICES:
                    svc_name, base_sev, note = RISKY_SERVICES[port.port]
                    actual_sev = "critical" if port.port in (4444, 23, 512, 513, 514) else base_sev
                    session.add_finding(
                        module="network.scanner",
                        target=f"{host.ip}:{port.port}/{port.protocol}",
                        title=f"Risky Port Open: {port.port}/{port.protocol} ({svc_name})",
                        description=(
                            f"Port {port.port} ({svc_name}) is open on {host.ip}.\n"
                            f"Service: {port.product} {port.version}\n"
                            f"Note: {note}"
                        ),
                        severity=actual_sev,  # type: ignore
                        tags=["network", "port-scan", port.service.lower() if port.service else ""],
                        details={
                            "port": port.port,
                            "protocol": port.protocol,
                            "service": port.service,
                            "version": port.version,
                            "product": port.product,
                        },
                    )
