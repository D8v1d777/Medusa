"""Session management — SQLAlchemy session and finding persistence."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from medusa.engine.core.config import Config
from medusa.engine.core.models import FindingModel, SessionModel, init_db

__all__ = ["Session"]


class Session:
    """Manages an engagement session, including findings persistence."""

    def __init__(
        self,
        cfg: Config,
        session_id: str | None = None,
        name: str | None = None,
        operator: str | None = None,
        target: str | None = None,
        scope_ips: list[str] | None = None,
        scope_domains: list[str] | None = None,
        scope_cidrs: list[str] | None = None,
    ) -> None:
        """
        Initialize or resume a session.

        :param cfg: Current framework configuration.
        :param session_id: UUID of an existing session to resume.
        :param name: Engagement name (for new sessions).
        :param operator: Operator name (for new sessions).
        :param target: Primary target (for new sessions).
        :param scope_ips: Scope IPs (for new sessions).
        :param scope_domains: Scope domains (for new sessions).
        :param scope_cidrs: Scope CIDRs (for new sessions).
        """
        self.cfg = cfg
        self.db_session = init_db(cfg.database_url)

        scope_data = json.dumps(
            {
                "ips": scope_ips or cfg.scope.ips,
                "domains": scope_domains or cfg.scope.domains,
                "cidrs": scope_cidrs or cfg.scope.cidrs,
            },
            sort_keys=True,
        )
        self.scope_hash = hashlib.sha256(scope_data.encode()).hexdigest()

        if session_id:
            self.model = (
                self.db_session.query(SessionModel).filter_by(id=session_id).first()
            )
            if not self.model:
                raise ValueError(f"Session {session_id} not found.")
        else:
            self.model = SessionModel(
                name=name or cfg.engagement.name,
                operator=operator or cfg.engagement.operator,
                scope_hash=self.scope_hash,
                status="active",
                target=target or "",
                scope_ips=scope_ips or cfg.scope.ips,
                scope_domains=scope_domains or cfg.scope.domains,
                scope_cidrs=scope_cidrs or cfg.scope.cidrs,
            )
            self.db_session.add(self.model)
            self.db_session.commit()

    @property
    def id(self) -> str:
        """Session UUID."""
        return str(self.model.id)

    def add_finding(
        self,
        module: str,
        target: str,
        title: str,
        description: str,
        severity: Literal["critical", "high", "medium", "low", "info"],
        cvss_vector: str | None = None,
        cvss_score: float | None = None,
        payload: str | None = None,
        request: str | None = None,
        response: str | None = None,
        source: Literal["tool", "ai", "manual"] = "tool",
        confidence: Literal["high", "medium", "low"] = "high",
        cve_ids: list[str] | None = None,
        cwe_ids: list[str] | None = None,
        mitre_technique: str | None = None,
        owasp_category: str | None = None,
        tags: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> FindingModel:
        """
        Add a finding to the session and persist to DB immediately.

        :return: The created FindingModel instance.
        """
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
            cwe_ids=cwe_ids or [],
            mitre_technique=mitre_technique,
            owasp_category=owasp_category,
            tags=tags or [],
            details=details or {},
        )
        self.db_session.add(finding)
        self.db_session.commit()
        return finding

    def update_token_usage(self, tokens: int) -> None:
        """Track AI token usage for the session."""
        self.model.ai_token_usage = (self.model.ai_token_usage or 0) + tokens
        self.db_session.commit()

    def set_status(self, status: Literal["active", "paused", "complete"]) -> None:
        """Update session status."""
        self.model.status = status
        self.db_session.commit()

    def close(self) -> None:
        """Close the database connection."""
        self.db_session.close()
