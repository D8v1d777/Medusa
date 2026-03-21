from __future__ import annotations
import hashlib
import json
import asyncio
from datetime import datetime
from typing import Literal, Optional, List
from pentkit.core.models import SessionModel, FindingModel, init_db
from pentkit.core.config import Config
from pentkit.output.csv_exporter import CSVExporter

class Session:
    """Manages a pentesting session, including findings persistence."""
    
    def __init__(self, cfg: Config, session_id: Optional[str] = None):
        """
        Initialize or resume a session.
        
        :param cfg: Current framework configuration.
        :param session_id: UUID of an existing session to resume.
        """
        self.cfg = cfg
        self.db_session = init_db(cfg.database_url)
        
        # Calculate scope hash to detect changes on resume
        scope_data = json.dumps(cfg.scope.model_dump(), sort_keys=True)
        self.scope_hash = hashlib.sha256(scope_data.encode()).hexdigest()
        
        if session_id:
            self.model = self.db_session.query(SessionModel).filter_by(id=session_id).first()
            if not self.model:
                raise ValueError(f"Session {session_id} not found.")
            
            if self.model.scope_hash != self.scope_hash:
                import logging
                logging.getLogger(__name__).warning("Resuming session with a different scope configuration.")
        else:
            self.model = SessionModel(
                name=cfg.engagement.name,
                operator=cfg.engagement.operator,
                scope_hash=self.scope_hash,
                status="active"
            )
            self.db_session.add(self.model)
            self.db_session.commit()

        # Initialize CSV exporter for web findings
        self.csv_exporter = CSVExporter(self)

    @property
    def id(self) -> str:
        return self.model.id

    def add_finding(
        self,
        module: str,
        target: str,
        title: str,
        description: str,
        severity: Literal["critical", "high", "medium", "low", "info"],
        cvss_vector: Optional[str] = None,
        cvss_score: Optional[float] = None,
        payload: Optional[str] = None,
        request: Optional[str] = None,
        response: Optional[str] = None,
        source: Literal["tool", "ai", "manual"] = "tool",
        confidence: Literal["high", "medium", "low"] = "high",
        cve_ids: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        details: Optional[dict] = None
    ) -> FindingModel:
        """
        Add a finding to the session and persist to DB immediately.
        
        :return: The created FindingModel instance.
        """
        # Truncate request/response to 4KB as per spec
        req_trunc = request[:4096] if request else None
        res_trunc = response[:4096] if response else None

        finding = FindingModel(
            session_id=self.id,
            module=module,
            target=target,
            title=title,
            description=description,
            severity=severity,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            payload=payload,
            request=req_trunc,
            response=res_trunc,
            source=source,
            confidence=confidence,
            cve_ids=cve_ids or [],
            tags=tags or [],
            details=details or {}
        )
        self.db_session.add(finding)
        self.db_session.commit()

        # Incremental CSV write for web findings
        if module.startswith("web."):
            try:
                # Use a background task to not block the main execution flow
                # but the requirement says "Serialise CSV writes" and "One lock per export file"
                # Since write_row is async, we should handle it carefully.
                # In most cases, we'll be in an async loop already.
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self.csv_exporter.write_row(finding))
                else:
                    asyncio.run(self.csv_exporter.write_row(finding))
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"CSV export failed for finding {finding.id}: {e}")

        return finding

    def update_token_usage(self, tokens: int):
        """Track AI token usage for the session."""
        self.model.ai_token_usage += tokens
        self.db_session.commit()

    def set_status(self, status: Literal["active", "paused", "complete"]):
        """Update session status."""
        self.model.status = status
        self.db_session.commit()

    def close(self):
        """Close the database connection."""
        self.db_session.close()

__all__ = ["Session"]
