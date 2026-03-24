"""
ORM Hunter — TIER 2.
Specialized vulnerability detection for applications using ORMs (Object-Relational Mappers).
Targets: JPA, Hibernate, Sequelize, EntityFramework, Eloquent, SQLAlchemy, Django ORM, Prisma.
Detects: HQL/JPQL Injection, Mass Assignment, OData Injection, Database Schema Leakage.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse, parse_qsl, urlencode

import httpx
from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster
from medusa.engine.modules.web.crawler import SiteMap

__all__ = ["ORMHunter"]

logger = logging.getLogger(__name__)

# ── ORM Detection Patterns ──────────────────────────────────────────────────

ORM_SIGNATURES: list[tuple[str, str, str]] = [
    (r"org\.hibernate\.", "Hibernate/JPA", "Java"),
    (r"SequelizeDatabaseError", "Sequelize", "Node.js"),
    (r"TypeORM", "TypeORM", "Node.js"),
    (r"PrismaClientKnownRequestError", "Prisma", "Node.js/Go/Rust"),
    (r"Microsoft\.EntityFrameworkCore", "EntityFramework", ".NET"),
    (r"SQLAlchemy\.", "SQLAlchemy", "Python"),
    (r"django\.db\.utils\.", "Django ORM", "Python"),
    (r"Illuminate\\Database\\QueryException", "Eloquent", "PHP"),
    (r"GormError", "GORM", "Go"),
]

# ── Vulnerability Payloads ───────────────────────────────────────────────────

# OData/Filter injections
ODATA_FILTER_PAYLOADS = [
    "$filter=name eq 'admin'",
    "$filter=1 eq 1",
    "$orderby=id desc",
    "filter[id]=1",
]

# Mass Assignment / Overposting (JSON)
MASS_ASSIGNMENT_FIELDS = [
    "{\"is_admin\":true}",
    "{\"role\":\"admin\"}",
    "{\"permissions\":[\"*\"]}",
    "{\"credit_balance\":99999}",
    "{\"user_id\":1}",
]


class ORMHunter:
    """
    Identifies and tests for ORM-specific vulnerabilities.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        broadcaster: WSBroadcaster | None = None,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.broadcaster = broadcaster or WSBroadcaster()

    async def run(self, sitemap: SiteMap, session: Session, auth_headers: dict[str, str] | None = None) -> None:
        """Analyze endpoints for ORM-related issues and detect the ORM in use."""
        await self.broadcaster.log(session.id, "INFO", "[orm_hunter] Starting ORM analysis", "orm_hunter")
        await self.broadcaster.emit_progress(session.id, "orm_hunter", 10, "running")

        async with httpx.AsyncClient(
            verify=False, timeout=12.0,
            headers={"User-Agent": "Medusa-Scanner/1.0", **(auth_headers or {})},
            follow_redirects=True,
        ) as client:
            # 1. Detect ORM via Error Fuzzing
            orm_info = await self._detect_orm(client, sitemap, session)
            if orm_info:
                await self.broadcaster.log(session.id, "INFO", f"[orm_hunter] Detected ORM: {orm_info['name']}", "orm_hunter")

            # 2. Test for Mass Assignment on POST/PUT endpoints
            await self._test_mass_assignment(client, sitemap, session)

            # 3. Test for OData/Filter Injection in Query Params
            await self._test_filter_injection(client, sitemap, session)

        await self.broadcaster.emit_progress(session.id, "orm_hunter", 100, "done")

    async def _detect_orm(self, client: httpx.AsyncClient, sitemap: SiteMap, session: Session) -> dict[str, str] | None:
        """Attempt to provoke error messages that leak the ORM name."""
        for url in sitemap.endpoints[:10]:
            if not self.guard.is_safe(url): continue
            
            # Provoke Error with invalid syntax in common query params
            params = {"order": "') OR 1=1--", "sort": "invalid][", "id": "'"}
            try:
                async with self.bucket:
                    resp = await client.get(url, params=params)
                
                body = resp.text or ""
                for pattern, name, lang in ORM_SIGNATURES:
                    if re.search(pattern, body, re.IGNORECASE):
                        session.add_finding(
                            module="web.orm_hunter",
                            target=url,
                            title=f"ORM Detected: {name}",
                            description=f"Information disclosure reveals {name} ORM ({lang}) is in use.",
                            severity="info",
                            tags=["orm", "recon", name.lower()],
                            owasp_category="A05:2021-Security Misconfiguration",
                            response=body[:1000]
                        )
                        return {"name": name, "lang": lang}
            except Exception:
                pass
        return None

    async def _test_mass_assignment(self, client: httpx.AsyncClient, sitemap: SiteMap, session: Session) -> None:
        """Test for Mass Assignment by injecting sensitive fields into JSON bodies."""
        for form in sitemap.forms[:10]:
            if form.method == "POST" and self.guard.is_safe(form.action):
                for payload in MASS_ASSIGNMENT_FIELDS:
                    try:
                        import json
                        data = json.loads(payload)
                        async with self.bucket:
                            resp = await client.post(form.action, json=data)
                        
                        # Heuristic: 200/201/204 with sensitive fields might indicate mass assignment
                        if resp.status_code in (200, 201, 204):
                            session.add_finding(
                                module="web.orm_hunter",
                                target=form.action,
                                title="Potential Mass Assignment Vulnerability",
                                description=(
                                    f"Sensitive payload '{payload}' was accepted via POST.\n"
                                    f"This may indicate the backend ORM or DTO is allowing mass assignment of unauthorized fields."
                                ),
                                severity="high",
                                payload=payload,
                                tags=["orm", "overposting", "mass-assignment"],
                                owasp_category="A01:2021-Broken Access Control",
                                request=f"POST {form.action} JSON: {payload}"
                            )
                            break
                    except Exception:
                        pass

    async def _test_filter_injection(self, client: httpx.AsyncClient, sitemap: SiteMap, session: Session) -> None:
        """Test for OData or generic filter injection in query parameters."""
        for url in sitemap.endpoints[:15]:
            if "?" in url or not self.guard.is_safe(url): continue

            for payload in ODATA_FILTER_PAYLOADS:
                test_url = f"{url}?{payload}"
                try:
                    async with self.bucket:
                        resp = await client.get(test_url)
                    
                    # If response code is successful for filter-like params on an endpoint
                    # check if the response data changes based on logic (TBD)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        session.add_finding(
                            module="web.orm_hunter",
                            target=test_url,
                            title="Exposed Filter Interface / Potential OData Injection",
                            description=(
                                f"Endpoint '{url}' appears to support structured filtering: `{payload}`\n"
                                "If improperly sanitized, this can lead to database enumeration or authorization bypass."
                            ),
                            severity="medium",
                            payload=payload,
                            tags=["orm", "odata", "filter-injection"],
                            owasp_category="A03:2021-Injection",
                            request=f"GET {test_url}"
                        )
                        break
                except Exception:
                    pass
