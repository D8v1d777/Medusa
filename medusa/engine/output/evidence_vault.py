"""Evidence vault — chain-of-custody storage."""
from __future__ import annotations

import json
import os
from pathlib import Path

from medusa.engine.core.config import get_config

__all__ = ["EvidenceVault"]


class EvidenceVault:
    """Append-only evidence storage."""

    def __init__(self, session_id: str) -> None:
        cfg = get_config()
        self.base = Path(os.path.expanduser(cfg.output.evidence_dir)) / session_id
        self.base.mkdir(parents=True, exist_ok=True)
        self.findings_path = self.base / "findings.jsonl"

    def add_finding(self, finding: dict) -> None:
        """Append finding to JSONL."""
        with open(self.findings_path, "a") as f:
            f.write(json.dumps(finding) + "\n")
