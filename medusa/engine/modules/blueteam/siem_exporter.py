"""SIEM export — Splunk, Elastic, Sentinel, QRadar, Sumo Logic."""
from __future__ import annotations

from medusa.engine.modules.blueteam.sigma_generator import SIGMAGenerator

__all__ = ["SIEMExporter"]


class SIEMExporter:
    """Export rules to SIEM-specific formats."""

    def __init__(self) -> None:
        self.sigma = SIGMAGenerator()

    def to_splunk(self, sigma_rule: str) -> str:
        """Translate to Splunk SPL."""
        return self.sigma.translate(sigma_rule, "splunk")

    def to_elastic(self, sigma_rule: str) -> str:
        """Translate to Elastic KQL."""
        return self.sigma.translate(sigma_rule, "elastic")

    def to_sentinel(self, sigma_rule: str) -> str:
        """Translate to Microsoft Sentinel KQL."""
        return self.sigma.translate(sigma_rule, "sentinel")

    def to_qradar(self, sigma_rule: str) -> str:
        """Translate to QRadar AQL."""
        return self.sigma.translate(sigma_rule, "qradar")

    def to_sumologic(self, sigma_rule: str) -> str:
        """Translate to Sumo Logic."""
        return self.sigma.translate(sigma_rule, "sumologic")
