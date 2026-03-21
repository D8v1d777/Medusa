import nmap
import httpx
import json
import asyncio
from typing import List, Dict, Optional
from dataclasses import dataclass
from pentkit.core.session import Session, Finding
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import rate_limiter

logger = get_module_logger("network.scanner")

@dataclass
class HostProfile:
    ip: str
    hostname: str
    os: str
    ports: List[Dict]

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def _query_nvd(self, cpe: str) -> List[Dict]:
        """Query NVD API for CVEs matching a CPE string."""
        # In real implementation, add caching to disk
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(self.nvd_api_url, params={"cpeName": cpe})
                if response.status_code == 200:
                    data = response.json()
                    return data.get('vulnerabilities', [])
            except Exception as e:
                logger.debug(f"NVD query failed for {cpe}: {e}")
        return []

    async def run(self, target: str, session: Session, evasion_flags: str = "") -> List[HostProfile]:
        logger.info(f"Starting network scan on {target}", extra={"target": target})
        
        # Default scan arguments
        args = f"-sS -O -sV {evasion_flags}".strip()
        
        # nmap.PortScanner.scan is blocking, run in executor
        loop = asyncio.get_event_loop()
        try:
            scan_data = await loop.run_in_executor(None, self.nm.scan, target, None, args)
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}", extra={"target": target})
            return []

        profiles = []
        for host in self.nm.all_hosts():
            ports = []
            for proto in self.nm[host].all_protocols():
                lport = self.nm[host][proto].keys()
                for port in lport:
                    service = self.nm[host][proto][port]
                    cpe = service.get('cpe', '')
                    ports.append({
                        'port': port,
                        'name': service.get('name'),
                        'product': service.get('product'),
                        'version': service.get('version'),
                        'cpe': cpe
                    })
                    
                    if cpe:
                        cves = await self._query_nvd(cpe)
                        for cve in cves:
                            cve_id = cve.get('cve', {}).get('id')
                            cvss_data = cve.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0]
                            cvss_vector = cvss_data.get('cvssData', {}).get('vectorString', '')
                            severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'MEDIUM')
                            
                            session.add_finding(Finding(
                                module="network.scanner", target=host, severity=severity,
                                payload=cpe, request=f"Nmap Scan {port}/{proto}",
                                response=f"Found CVE {cve_id}", cvss_vector=cvss_vector,
                                details={"cve_id": cve_id, "port": port, "service": service.get('name')}
                            ))

            profile = HostProfile(
                ip=host,
                hostname=self.nm[host].hostname(),
                os=self.nm[host].get('osmatch', [{}])[0].get('name', 'Unknown'),
                ports=ports
            )
            profiles.append(profile)
            
        return profiles
