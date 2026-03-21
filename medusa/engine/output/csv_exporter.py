"""CSV exporter for findings."""
from __future__ import annotations

import csv
import os
from pathlib import Path

from medusa.engine.core.config import get_config
from medusa.engine.core.models import FindingModel

__all__ = ["CSVExporter"]


class CSVExporter:
    """Export findings to CSV."""

    def __init__(self, session: object) -> None:
        self.session = session
        cfg = get_config()
        self.output_dir = Path(os.path.expanduser(cfg.output.report_dir))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, findings: list[FindingModel], path: Path | None = None) -> Path:
        """Export findings to CSV."""
        p = path or self.output_dir / "findings.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "module", "target", "title", "severity", "cvss_score"])
            for r in findings:
                w.writerow([
                    r.id, r.module, r.target, r.title,
                    r.severity, r.cvss_score,
                ])
        return p
