"""YARA rule generator."""
from __future__ import annotations

from medusa.engine.core.models import FindingModel

__all__ = ["YARAGenerator"]


class YARAGenerator:
    """Generates YARA rules from findings."""

    def generate(
        self, finding: FindingModel, payload: str | None = None
    ) -> str:
        """Generate YARA rule for payload/IOC."""
        p = payload or finding.payload or "unknown"
        safe = p.replace("\\", "\\\\").replace('"', '\\"')[:200]
        return f'''rule {finding.module.replace(".", "_")}_{finding.id[:8]} {{
    meta:
        description = "{finding.title}"
        severity = "{finding.severity}"
        author = "Medusa"
    strings:
        $a = "{safe}"
    condition:
        any of them
}}
'''
