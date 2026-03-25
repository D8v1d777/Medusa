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
    """
    Generates SIGMA rules from findings and translates them to SIEM query languages.
    Uses pySigma (the official Python implementation) or sigma-cli.
    """

    def generate(self, finding: FindingModel, detection: DetectionArtifact) -> str:
        """
        Produce a valid SIGMA YAML rule from finding metadata.
        Ensures all mandatory fields (id, title, status, description, logsource, detection) are present.
        """
        import uuid
        from datetime import datetime

        # 1. Basic Metadata
        rule_id = str(uuid.uuid4())
        title = str(getattr(finding, "title", "Generic Finding"))
        description = str(getattr(finding, "description", "No description provided"))
        author = "Medusa Security Framework"
        date = datetime.now().strftime("%Y/%m/%d")
        
        # 2. Level mapping from CVSS (Blueprint Rule 8)
        raw_cvss = getattr(finding, "cvss_score", None)
        cvss_score = float(raw_cvss) if raw_cvss else 0.0
        level = _cvss_to_level(cvss_score)

        # 3. MITRE Mapping (Blueprint Rule 3)
        mitre_tech = str(getattr(finding, "mitre_technique", "T1190"))
        
        # 4. Construct the YAML
        # We start with the findings specific detection provided by the engine
        # and wrap it in the standard SIGMA envelope.
        yaml_rule = f"""title: {title}
id: {rule_id}
status: experimental
description: |
  {description[:500]}
references:
  - https://github.com/medusa-security/medusa
author: {author}
date: {date}
logsource:
  category: webserver
  product: generic
detection:
{detection.sigma_rule if detection.sigma_rule else '  selection:\\n    request_url|contains: "medusa-scan"\\n  condition: selection'}
falsepositives:
  - {detection.false_positive_risk or "Legitimate security testing, administrative access"}
level: {level}
tags:
  - attack.{mitre_tech.lower()}
"""
        return yaml_rule

    def translate(self, sigma_rule: str, target_siem: str) -> str:
        """
        Translate a SIGMA rule to a target SIEM query (Splunk, Elastic, Sentinel).
        Uses sigma-cli subprocess for the most accurate translation.
        """
        import subprocess
        import tempfile
        import os
        from pathlib import Path

        # Map internal target names to sigma-cli targets
        target_map = {
            "splunk": "splunk",
            "elastic": "elasticsearch",
            "sentinel": "microsoft_sentinel",
            "qradar": "qradar",
            "crowdstrike": "crowdstrike",
        }
        
        sigma_target = target_map.get(target_siem.lower(), "splunk")

        # 1. Create a temporary file for the rule
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode='w', encoding='utf-8') as tf:
            tf.write(sigma_rule)
            rule_path = tf.name
        
        try:
            # 2. Run sigma-cli to translate
            # .venv/Scripts/sigma.exe is where it's installed
            sigma_bin = str(Path(".venv/Scripts/sigma.exe")) if os.name == "nt" else "sigma"
            
            cmd = [sigma_bin, "convert", "-t", sigma_target, "-o", "json", rule_path]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if proc.returncode == 0:
                # Some backends output raw strings, others JSON.
                return proc.stdout.strip()
            else:
                logger.error("Sigma translation failed: %s", proc.stderr)
                # Fallback to a very basic string if conversion fails
                return f"// Translation failed. Raw rule below:\n{sigma_rule}"
        except Exception as e:
            logger.error("Error in sigma translation: %s", e)
            return f"// Error: {str(e)}"
        finally:
            try:
                os.unlink(rule_path)
            except:
                pass
