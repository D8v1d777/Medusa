"""
CVE Correlator — TIER 4.
Queries NVD API v2 and ExploitDB for CVEs by service/product/version.
Returns structured CVECorrelation objects with CVSS scores and exploit availability.
"""
from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx

__all__ = ["CVECorrelator", "CVECorrelation", "ExploitInfo"]

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_API = "https://www.exploit-db.com/search"
OSVDB_API = "https://osv.dev/v1/query"


@dataclass
class ExploitInfo:
    """Exploit database entry."""
    source: str
    exploit_id: str
    title: str
    url: str
    verified: bool = False
    exploit_type: str = ""


@dataclass
class CVECorrelation:
    """CVE correlation result with full metadata."""
    cve_id: str
    cvss_score: float
    cvss_vector: str = ""
    severity: str = ""
    description: str = ""
    published: str = ""
    modified: str = ""
    has_exploit: bool = False
    exploit_url: str | None = None
    exploits: list[ExploitInfo] = field(default_factory=list)
    patch_available: bool = False
    cpe_list: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0:
        return "low"
    return "info"


class CVECorrelator:
    """
    Real-time CVE and exploit lookup.
    Sources: NVD API v2, ExploitDB search, OSV.dev.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key  # NVD API key for higher rate limits
        self._cache: dict[str, list[CVECorrelation]] = {}

    async def lookup(
        self,
        cpe: str | None = None,
        product: str = "",
        version: str = "",
        max_results: int = 10,
    ) -> list[CVECorrelation]:
        """
        Look up CVEs for a product/version or CPE string.
        Returns list sorted by CVSS score descending.
        """
        cache_key = f"{cpe}::{product}::{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results = await self._query_nvd(cpe=cpe, product=product, version=version, max_results=max_results)

        # Add exploit info
        for cve in results:
            exploits = await self._check_exploitdb(cve.cve_id)
            if exploits:
                cve.has_exploit = True
                cve.exploit_url = exploits[0].url
                cve.exploits = exploits

        results.sort(key=lambda c: c.cvss_score, reverse=True)
        self._cache[cache_key] = results[:max_results]
        return self._cache[cache_key]

    async def lookup_by_cve_id(self, cve_id: str) -> CVECorrelation | None:
        """Look up a specific CVE ID."""
        cache_key = f"cve::{cve_id}"
        if cache_key in self._cache:
            return self._cache[cache_key][0] if self._cache[cache_key] else None

        results = await self._query_nvd_by_id(cve_id)
        if results:
            self._cache[cache_key] = results
            return results[0]
        return None

    async def _query_nvd(
        self,
        cpe: str | None,
        product: str,
        version: str,
        max_results: int,
    ) -> list[CVECorrelation]:
        """Query NVD API v2."""
        headers = {"User-Agent": "Medusa-Scanner/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params: dict[str, Any] = {"resultsPerPage": max_results, "startIndex": 0}
        if cpe:
            params["cpeName"] = cpe
        elif product:
            query = f"{product} {version}".strip()
            params["keywordSearch"] = query
            params["keywordExactMatch"] = ""

        try:
            async with httpx.AsyncClient(timeout=15, headers=headers) as client:
                resp = await client.get(NVD_API_BASE, params=params)
                if resp.status_code == 403:
                    logger.warning("NVD API rate limited — add API key for higher limits")
                    return []
                if resp.status_code != 200:
                    logger.warning("NVD API returned %d", resp.status_code)
                    return []
                data = resp.json()
        except Exception as exc:
            logger.warning("NVD API error: %s", exc)
            return []

        return self._parse_nvd_response(data)

    async def _query_nvd_by_id(self, cve_id: str) -> list[CVECorrelation]:
        """Query NVD API by specific CVE ID."""
        headers = {"User-Agent": "Medusa-Scanner/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            async with httpx.AsyncClient(timeout=10, headers=headers) as client:
                resp = await client.get(f"{NVD_API_BASE}?cveId={cve_id}")
                if resp.status_code == 200:
                    return self._parse_nvd_response(resp.json())
        except Exception as exc:
            logger.debug("NVD ID lookup failed: %s", exc)
        return []

    def _parse_nvd_response(self, data: dict) -> list[CVECorrelation]:
        correlations = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # Description
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            # CVSS
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            cvss_vector = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key, [])
                if arr:
                    cvss_data = arr[0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0))
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            # References
            refs = [r.get("url", "") for r in cve.get("references", [])[:5]]

            # CPE matches
            cpes = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            cpes.append(match.get("criteria", ""))

            correlations.append(CVECorrelation(
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=_cvss_to_severity(cvss_score),
                description=desc[:1000],
                published=cve.get("published", ""),
                modified=cve.get("lastModified", ""),
                cpe_list=cpes[:5],
                references=refs,
                patch_available=any("patch" in r.lower() or "fix" in r.lower() for r in refs),
            ))
        return correlations

    async def _check_exploitdb(self, cve_id: str) -> list[ExploitInfo]:
        """Check ExploitDB for public exploits for a CVE."""
        exploits = []
        try:
            async with httpx.AsyncClient(timeout=10, headers={"User-Agent": "Medusa-Scanner/1.0"}) as client:
                # ExploitDB search via their API
                resp = await client.get(
                    EXPLOITDB_API,
                    params={"cve": cve_id.replace("CVE-", ""), "draw": 1, "length": 5},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        eid = str(item.get("id", ""))
                        title = item.get("description", "") or item.get("title", "")
                        if eid:
                            exploits.append(ExploitInfo(
                                source="exploit-db",
                                exploit_id=eid,
                                title=str(title)[:200],
                                url=f"https://www.exploit-db.com/exploits/{eid}",
                                verified=bool(item.get("verified")),
                                exploit_type=str(item.get("type", "")),
                            ))
        except Exception as exc:
            logger.debug("ExploitDB check failed for %s: %s", cve_id, exc)
        return exploits

    async def bulk_lookup_services(
        self,
        services: list[dict[str, str]],
        session: Any = None,
    ) -> dict[str, list[CVECorrelation]]:
        """
        Bulk CVE lookup for multiple services in parallel.
        `services` is a list of dicts with 'product', 'version', 'cpe' keys.
        Returns dict keyed by "product:version".
        """
        results: dict[str, list[CVECorrelation]] = {}
        semaphore = asyncio.Semaphore(3)  # NVD rate limit

        async def _lookup_one(svc: dict) -> tuple[str, list[CVECorrelation]]:
            async with semaphore:
                await asyncio.sleep(0.5)  # NVD rate limit: 5 req/30s without key
                cves = await self.lookup(
                    cpe=svc.get("cpe"),
                    product=svc.get("product", ""),
                    version=svc.get("version", ""),
                )
                key = f"{svc.get('product', 'unknown')}:{svc.get('version', '')}"
                return key, cves

        tasks = [_lookup_one(svc) for svc in services]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for r in responses:
            if isinstance(r, tuple):
                results[r[0]] = r[1]
        return results
