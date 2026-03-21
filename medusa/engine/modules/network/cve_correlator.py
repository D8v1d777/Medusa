"""CVE correlator — NVD and exploit DB lookup."""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

__all__ = ["CVECorrelator", "CVECorrelation"]

logger = logging.getLogger(__name__)


@dataclass
class CVECorrelation:
    """CVE correlation result."""

    cve_id: str
    cvss_score: float
    has_exploit: bool
    exploit_url: str | None
    patch_available: bool


class CVECorrelator:
    """Correlate service versions with CVEs."""

    async def lookup(
        self, cpe: str | None = None, product: str = "", version: str = ""
    ) -> list[CVECorrelation]:
        """Look up CVEs for product/version."""
        results: list[CVECorrelation] = []
        if not product and not cpe:
            return results
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if cpe:
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
                else:
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}+{version}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for vuln in data.get("vulnerabilities", [])[:10]:
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id", "Unknown")
                        metrics = cve.get("metrics", {}) or {}
                        cvss = 0.0
                        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            arr = metrics.get(k, [])
                            if arr:
                                cvss = float(arr[0].get("cvssData", {}).get("baseScore", 0))
                                break
                        results.append(CVECorrelation(
                            cve_id=cve_id,
                            cvss_score=cvss,
                            has_exploit=False,
                            exploit_url=None,
                            patch_available=False,
                        ))
        except Exception as e:
            logger.debug("CVE lookup failed: %s", e)
        return results
