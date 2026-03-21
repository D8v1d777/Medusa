"""Jira ticket export."""
from __future__ import annotations

import logging

import httpx

from medusa.engine.core.models import FindingModel

__all__ = ["create_tickets"]

logger = logging.getLogger(__name__)


async def create_tickets(
    findings: list[FindingModel],
    jira_url: str,
    project_key: str,
    token: str,
) -> list[str]:
    """Create Jira tickets from findings. Returns ticket keys."""
    keys: list[str] = []
    async with httpx.AsyncClient() as client:
        for f in findings[:50]:
            try:
                resp = await client.post(
                    f"{jira_url}/rest/api/3/issue",
                    json={
                        "fields": {
                            "project": {"key": project_key},
                            "summary": f"[{f.severity.upper()}] {f.title} — {f.target}",
                            "description": f.description or "",
                            "issuetype": {"name": "Bug"},
                        }
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code in (200, 201):
                    keys.append(resp.json().get("key", ""))
            except Exception as e:
                logger.error("Jira create failed: %s", e)
    return keys
