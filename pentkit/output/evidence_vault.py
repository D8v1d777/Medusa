import json
import os
from pathlib import Path
from pentkit.core.session import Session, Finding
from pentkit.core.logger import get_module_logger

logger = get_module_logger("output.evidence_vault")

class EvidenceVault:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.base_dir = Path.home() / ".pentkit" / "evidence" / session_id
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save_finding(self, finding: Finding):
        """Save a finding as a JSON file in the vault."""
        finding_id = getattr(finding, 'id', 'finding_' + os.urandom(4).hex())
        finding_file = self.base_dir / f"{finding_id}.json"
        
        # Never overwrite
        if finding_file.exists():
            logger.warning(f"Finding {finding_id} already exists in vault. Skipping.")
            return

        data = {
            "module": finding.module,
            "target": finding.target,
            "severity": finding.severity,
            "payload": finding.payload,
            "request": finding.request,
            "response": finding.response,
            "cvss_vector": finding.cvss_vector,
            "details": finding.details
        }
        
        with open(finding_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.debug(f"Saved finding to {finding_file}")

    def save_screenshot(self, name: str, binary_data: bytes):
        """Save a screenshot to the vault."""
        screenshot_file = self.base_dir / f"{name}.png"
        with open(screenshot_file, 'wb') as f:
            f.write(binary_data)
        logger.debug(f"Saved screenshot to {screenshot_file}")

    def save_pcap(self, name: str, binary_data: bytes):
        """Save a PCAP excerpt to the vault."""
        pcap_file = self.base_dir / f"{name}.pcap"
        with open(pcap_file, 'wb') as f:
            f.write(binary_data)
        logger.debug(f"Saved PCAP to {pcap_file}")
