"""IOC extractor — network, host, web, credential IOCs."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from medusa.engine.core.models import FindingModel, SessionModel
from medusa.engine.core.models import init_db
from medusa.engine.core.config import get_config

__all__ = ["IOCExtractor", "IOCReport"]

@dataclass
class IOCEntry:
    """Single IOC."""

    type: str
    value: str
    source_finding_id: str
    severity: str
    confidence: float = 1.0


@dataclass
class IOCReport:
    """Full IOC report."""

    session_id: str
    network: list[IOCEntry] = field(default_factory=list)
    host: list[IOCEntry] = field(default_factory=list)
    web: list[IOCEntry] = field(default_factory=list)
    credential: list[IOCEntry] = field(default_factory=list)


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|net|org|io|xyz|dev)\b")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


class IOCExtractor:
    """Extracts IOCs from findings."""

    async def extract(self, session: SessionModel) -> IOCReport:
        """Extract IOCs from all findings in session."""
        db = init_db(get_config().database_url)
        try:
            findings = db.query(FindingModel).filter_by(
                session_id=str(getattr(session, "id", ""))
            ).all()

            report = IOCReport(session_id=str(getattr(session, "id", "")))

            for f in findings:
                fid = str(getattr(f, "id", ""))
                severity_val = str(getattr(f, "severity", None) or "")
                texts = [
                    str(getattr(f, "target", None) or ""),
                    str(getattr(f, "payload", None) or ""),
                    str(getattr(f, "request", None) or ""),
                    str(getattr(f, "response", None) or ""),
                    str(getattr(f, "details", None) or {}),
                ]
                combined = " ".join(texts)
                for m in IP_PATTERN.finditer(combined):
                    report.network.append(
                        IOCEntry("ip", m.group(), fid, severity_val)
                    )
                for m in DOMAIN_PATTERN.finditer(combined):
                    report.web.append(
                        IOCEntry("domain", m.group(), fid, severity_val)
                    )
                for m in HASH_PATTERN.finditer(combined):
                    if len(m.group()) in (32, 40, 64):
                        report.credential.append(
                            IOCEntry("hash", m.group(), fid, severity_val)
                        )

            return report
        finally:
            db.close()
