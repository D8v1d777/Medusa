"""Detection engine — converts findings to detection opportunities."""
from __future__ import annotations

import uuid
import logging
from dataclasses import dataclass, field
from typing import Literal

from medusa.engine.core.models import FindingModel

__all__ = ["DetectionEngine", "DetectionArtifact", "HardeningItem"]

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """Indicator of compromise."""

    type: str
    value: str
    source: str


@dataclass
class HardeningItem:
    """Hardening recommendation."""

    category: str
    title: str
    finding_ids: list[str]
    current_state: str
    recommended_control: str
    implementation_effort: Literal["Low", "Medium", "High"]
    mitre_technique: str | None


@dataclass
class DetectionArtifact:
    """Output of detection engine."""

    sigma_rule: str
    yara_rule: str | None
    iocs: list[IOC] = field(default_factory=list)
    log_patterns: list[str] = field(default_factory=list)
    detection_difficulty: Literal["easy", "medium", "hard", "unlikely"] = "medium"
    false_positive_risk: str = ""
    hardening: HardeningItem | None = None


class DetectionEngine:
    """
    Runs after each offensive module completes.
    Converts findings into detection opportunities.
    """

    async def process_finding(
        self, finding: FindingModel
    ) -> DetectionArtifact:
        """Route finding to appropriate detector based on type."""
        tags_raw = getattr(finding, "tags", None)
        tags_list: list[str] = list(tags_raw) if isinstance(tags_raw, list) else []
        tags_str = " ".join(str(t) for t in tags_list).lower()
        title_val: str = str(getattr(finding, "title", None) or "")
        if "sqli" in tags_str or "sql" in title_val.lower():
            return self._detect_sqli(finding)
        if "xss" in tags_str:
            return self._detect_xss(finding)
        if "ssrf" in tags_str:
            return self._detect_ssrf(finding)
        if "kerberoast" in tags_str:
            return self._detect_kerberoasting(finding)
        if "arp" in tags_str:
            return self._detect_arp_poison(finding)
        if "ad_cs" in tags_str or "esc1" in str(tags_list).lower():
            return self._detect_ad_cs_abuse(finding)
        return self._generic_detection(finding)

    def _detect_sqli(self, finding: FindingModel) -> DetectionArtifact:
        """SQL injection detection."""
        sigma = f"""title: SQL Injection - URL Parameter
id: {uuid.uuid4()}
status: experimental
description: Detects SQL keywords in access logs
logsource:
  category: webserver
  product: generic
detection:
  selection:
    request_url|contains:
      - 'SELECT'
      - 'UNION'
      - 'OR 1=1'
  condition: selection
falsepositives:
  - Legitimate URLs with SQL-like parameters
level: high
tags:
  - attack.T1190
"""
        return DetectionArtifact(
            sigma_rule=sigma,
            yara_rule=None,
            log_patterns=["SELECT|INSERT|UPDATE|DELETE|UNION|DROP in URL params"],
            detection_difficulty="easy",
            false_positive_risk="SQL keywords in legitimate URLs",
            hardening=HardeningItem(
                category="Application",
                title="Parameterised queries",
                finding_ids=[str(finding.id)],
                current_state="Raw SQL concatenation",
                recommended_control="Use parameterised queries, WAF rule, input validation",
                implementation_effort="Medium",
                mitre_technique="T1190",
            ),
        )

    def _detect_xss(self, finding: FindingModel) -> DetectionArtifact:
        """XSS detection."""
        sigma = f"""title: XSS Payload in Request
id: {uuid.uuid4()}
status: experimental
description: Script tags in request params
logsource:
  category: webserver
  product: generic
detection:
  selection:
    request_url|contains:
      - '<script>'
      - 'javascript:'
      - 'onerror='
  condition: selection
level: high
tags:
  - attack.T1059
"""
        return DetectionArtifact(
            sigma_rule=sigma,
            yara_rule=None,
            iocs=(
                [IOC("string", payload_val, "xss_payload")]
                if (payload_val := str(getattr(finding, "payload", None) or ""))
                else []
            ),
            log_patterns=["<script>, javascript:, onerror= in request"],
            detection_difficulty="easy",
            false_positive_risk="Legitimate script references",
            hardening=HardeningItem(
                category="Application",
                title="CSP and output encoding",
                finding_ids=[str(finding.id)],
                current_state="Unvalidated output",
                recommended_control="CSP header, output encoding, X-XSS-Protection",
                implementation_effort="Low",
                mitre_technique="T1059",
            ),
        )

    def _detect_ssrf(self, finding: FindingModel) -> DetectionArtifact:
        """SSRF detection."""
        sigma = f"""title: SSRF - Internal Range Request
id: {uuid.uuid4()}
status: experimental
description: Web server requesting internal IP ranges
logsource:
  category: firewall
  product: generic
detection:
  selection:
    dst_ip|startswith:
      - '169.254.'
      - '10.'
      - '192.168.'
  condition: selection
level: high
tags:
  - attack.T1190
"""
        return DetectionArtifact(
            sigma_rule=sigma,
            yara_rule=None,
            log_patterns=["Outbound requests to 169.254.0.0/16 or RFC1918 from web server"],
            detection_difficulty="medium",
            false_positive_risk="Legitimate backend calls",
            hardening=HardeningItem(
                category="Network",
                title="Egress firewall",
                finding_ids=[str(finding.id)],
                current_state="Unrestricted outbound from web tier",
                recommended_control="Egress firewall rules, IMDS v2 enforcement",
                implementation_effort="Medium",
                mitre_technique="T1190",
            ),
        )

    def _detect_kerberoasting(self, finding: FindingModel) -> DetectionArtifact:
        """Kerberoasting detection."""
        sigma = f"""title: Kerberoasting - RC4 TGS Request
id: {uuid.uuid4()}
status: experimental
description: Windows Event 4769 with RC4 encryption
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  condition: selection
level: high
tags:
  - attack.T1558
"""
        return DetectionArtifact(
            sigma_rule=sigma,
            yara_rule=None,
            log_patterns=["Event ID 4769, Encryption 0x17 (RC4)"],
            detection_difficulty="easy",
            false_positive_risk="Legacy apps using RC4",
            hardening=HardeningItem(
                category="Identity",
                title="AES-only service accounts",
                finding_ids=[str(finding.id)],
                current_state="RC4 permitted for TGS",
                recommended_control="Use AES-only, gMSA",
                implementation_effort="Medium",
                mitre_technique="T1558",
            ),
        )

    def _detect_arp_poison(self, finding: FindingModel) -> DetectionArtifact:
        """ARP poisoning detection."""
        sigma = f"""title: ARP Spoofing - Gratuitous ARP
id: {uuid.uuid4()}
status: experimental
description: ARP reply sender MAC mismatch
logsource:
  category: network
  product: generic
detection:
  selection:
    arp_opcode: 2
  condition: selection
level: medium
tags:
  - attack.T1557
"""
        return DetectionArtifact(
            sigma_rule=sigma,
            yara_rule=None,
            log_patterns=["Gratuitous ARP not matching DHCP lease"],
            detection_difficulty="easy",
            false_positive_risk="VM migration, failover",
            hardening=HardeningItem(
                category="Network",
                title="Dynamic ARP Inspection",
                finding_ids=[str(finding.id)],
                current_state="No DAI",
                recommended_control="DAI on switches, static ARP for gateways",
                implementation_effort="Medium",
                mitre_technique="T1557",
            ),
        )

    def _detect_ad_cs_abuse(self, finding: FindingModel) -> DetectionArtifact:
        """AD CS abuse detection."""
        sigma = f"""title: AD CS ESC1 - SAN Mismatch
id: {uuid.uuid4()}
status: experimental
description: Event 4887 where SAN != requestor UPN
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4887
  condition: selection
level: critical
tags:
  - attack.T1649
"""
        return DetectionArtifact(
            sigma_rule=sigma,
            yara_rule=None,
            log_patterns=["Event 4886/4887 with unusual SAN"],
            detection_difficulty="medium",
            false_positive_risk="Legitimate cert requests",
            hardening=HardeningItem(
                category="Identity",
                title="Disable EDITF_ATTRIBUTESUBJECTALTNAME2",
                finding_ids=[str(finding.id)],
                current_state="Vulnerable template",
                recommended_control="Disable flag, require manager approval",
                implementation_effort="High",
                mitre_technique="T1649",
            ),
        )

    def _generic_detection(self, finding: FindingModel) -> DetectionArtifact:
        """Generic detection fallback."""
        title_val = str(getattr(finding, "title", None) or "")
        return DetectionArtifact(
            sigma_rule=f"title: Generic - {title_val}\nid: {uuid.uuid4()}\nstatus: experimental\n",
            yara_rule=None,
            log_patterns=[],
            detection_difficulty="unlikely",
            false_positive_risk="Unknown",
        )
