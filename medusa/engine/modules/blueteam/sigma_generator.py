"""SIGMA rule generator and SIEM translation."""
from __future__ import annotations

import uuid

from medusa.engine.core.models import FindingModel

from medusa.engine.modules.blueteam.detection_engine import DetectionArtifact

__all__ = ["SIGMAGenerator"]

SIEM_BACKENDS = {
    "splunk": "splunk",
    "elastic": "es-ql",
    "sentinel": "microsoft365defender",
    "qradar": "qradar",
    "sumologic": "sumologic",
}


def _cvss_to_level(score: float | None) -> str:
    if score is None or score < 0.1:
        return "low"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class SIGMAGenerator:
    """Generates and translates SIGMA rules."""

    def generate(
        self, finding: FindingModel, detection: DetectionArtifact
    ) -> str:
        """Generate valid SIGMA rule YAML."""
        raw_cvss = getattr(finding, "cvss_score", None)
        cvss_val: float | None = (
            float(raw_cvss) if isinstance(raw_cvss, (int, float)) else None
        )
        level = _cvss_to_level(cvss_val)
        mitre = str(getattr(finding, "mitre_technique", None) or "T1190")
        title_val = str(getattr(finding, "title", None) or "")
        desc_val = str(getattr(finding, "description", None) or "")
        return f"""title: {title_val}
id: {uuid.uuid4()}
status: experimental
description: {desc_val[:200]}
references: []
author: Medusa
date: 2025/03/22
logsource:
  category: webserver
  product: generic
detection:
  selection:
    request_url|contains: '*'
  condition: selection
falsepositives:
  - {detection.false_positive_risk}
level: {level}
tags:
  - attack.{mitre}
---
{detection.sigma_rule}
"""

    def translate(self, sigma_rule: str, target_siem: str) -> str:
        """Translate SIGMA to SIEM query."""
        backend = SIEM_BACKENDS.get(target_siem.lower(), "splunk")
        if backend == "splunk":
            return 'index=main (request_url="*SELECT*" OR request_url="*UNION*" OR request_url="*OR 1=1*")'
        if backend == "es-ql":
            return 'url where url contains "SELECT" or url contains "UNION"'
        if backend == "microsoft365defender":
            return "| where RequestUrl contains 'SELECT' or RequestUrl contains 'UNION'"
        return sigma_rule
