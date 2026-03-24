"""
Active scanner orchestrator — TIER 1.
Equivalent to ZAP's Active Scan with a scanner policy.
Coordinates all detection modules in the correct sequence.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster
from medusa.engine.modules.web.authenticated_scanner import AuthContext

__all__ = ["ActiveScanner", "ScanResult", "SCAN_POLICIES"]

logger = logging.getLogger(__name__)

SCAN_POLICIES: dict[str, dict[str, Any]] = {
    "quick": {
        "description": "Fast scan — headers, known CVEs, obvious misconfigs",
        "template_categories": ["technologies", "exposed-panels", "misconfiguration"],
        "nuclei_severity": ["critical", "high"],
        "active_checks": ["header_analyzer", "waf_detector"],
        "estimated_time": "2-5 minutes",
    },
    "standard": {
        "description": "Balanced scan — most detection categories, common vulns",
        "template_categories": ["cves", "vulnerabilities", "misconfiguration",
                                "exposed-panels", "default-logins", "exposures"],
        "nuclei_severity": ["critical", "high", "medium"],
        "active_checks": ["header_analyzer", "waf_detector", "crawler",
                          "injectors", "auth_tester", "api_scanner"],
        "estimated_time": "15-45 minutes",
    },
    "deep": {
        "description": "Comprehensive — all templates, full fuzzing, API deep dive",
        "template_categories": ["all"],
        "nuclei_severity": ["critical", "high", "medium", "low"],
        "active_checks": ["header_analyzer", "waf_detector", "crawler",
                          "injectors", "auth_tester", "api_scanner", "llm_scanner", "race_tester"],
        "estimated_time": "1-4 hours",
    },
    "api": {
        "description": "API-focused — REST, GraphQL, authentication, authorization",
        "template_categories": ["vulnerabilities", "fuzzing"],
        "nuclei_severity": ["critical", "high", "medium"],
        "active_checks": ["api_scanner", "auth_tester", "injectors", "llm_scanner"],
        "estimated_time": "10-30 minutes",
    },
    "cve": {
        "description": "CVE-only — check for specific known vulnerabilities",
        "template_categories": ["cves"],
        "nuclei_severity": ["critical", "high"],
        "active_checks": [],
        "estimated_time": "5-15 minutes",
    },
}


@dataclass
class ScanResult:
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    scan_duration: float = 0.0
    coverage_score: float = 0.0
    policy: str = ""
    modules_run: list[str] = field(default_factory=list)


class ActiveScanner:
    """
    Orchestrates all active scanning modules.
    Analyst selects a scan policy (speed vs depth) and this runs accordingly.
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

    async def run(
        self,
        target: str,
        policy: str,
        auth_context: AuthContext | None,
        session: Session,
    ) -> ScanResult:
        """
        Execute active scan according to policy.

        Execution order within a policy:
        1. header_analyzer (passive, fast — always first)
        2. waf_detector (sets WAF context for all subsequent modules)
        3. crawler (builds sitemap — feeds all subsequent modules)
        4. template_engine (Nuclei templates — widest coverage)
        5. injectors (SQLi, XSS, SSRF, XXE, SSTI)
        6. auth_tester (if credentials provided)
        7. api_scanner (if API endpoints detected)
        8. js_analyzer (client-side analysis)
        9. orm_hunter (after crawler identifies tech stack)
        """
        policy_cfg = SCAN_POLICIES.get(policy, SCAN_POLICIES["standard"])
        checks = policy_cfg["active_checks"]
        run_all = "all" in checks

        result = ScanResult(policy=policy)
        start = time.monotonic()

        await self.broadcaster.log(
            session.id, "INFO",
            f"[active_scanner] Starting {policy.upper()} scan on {target}", "active_scanner",
        )
        await self.broadcaster.emit_progress(session.id, "active_scanner", 0, "running")

        auth_headers: dict[str, str] = auth_context.headers if auth_context else {}
        auth_cookies: dict[str, str] = auth_context.cookies if auth_context else {}

        # ── Step 1: Header Analyzer ──────────────────────────────────────
        if run_all or "header_analyzer" in checks:
            await self._run_step(session, "header_analyzer", 10,
                                 self._run_header_analyzer, target, session, auth_headers)
            result.modules_run.append("header_analyzer")

        # ── Step 2: WAF Detector ─────────────────────────────────────────
        waf_info: dict[str, Any] = {}
        if run_all or "waf_detector" in checks:
            waf_info = await self._run_step(session, "waf_detector", 20,
                                            self._run_waf_detector, target, session, auth_headers)
            result.modules_run.append("waf_detector")

        # ── Step 3: Crawler ───────────────────────────────────────────────
        sitemap: Any = None
        if run_all or "crawler" in checks:
            sitemap = await self._run_step(session, "crawler", 35,
                                           self._run_crawler, target, session)
            result.modules_run.append("crawler")

        # ── Step 4: Template Engine (Nuclei) ──────────────────────────────
        template_findings: list[Any] = []
        if True:  # always run templates
            cats = policy_cfg.get("template_categories", [])
            sevs = policy_cfg.get("nuclei_severity", ["critical", "high"])
            categories_arg = cats if "all" not in cats else None
            template_findings = await self._run_step(
                session, "template_engine", 55,
                self._run_template_engine,
                target, session, categories_arg, sevs, auth_headers,
            )
            result.modules_run.append("template_engine")

        # ── Step 5: Injectors ─────────────────────────────────────────────
        if run_all or "injectors" in checks:
            await self._run_step(session, "injectors", 65,
                                 self._run_injectors, sitemap, session, auth_headers, auth_cookies)
            result.modules_run.append("injectors")

        # ── Step 6: Auth Tester ───────────────────────────────────────────
        if auth_context and (run_all or "auth_tester" in checks):
            await self._run_step(session, "auth_tester", 75,
                                 self._run_auth_tester, target, session, auth_headers)
            result.modules_run.append("auth_tester")

        # ── Step 7: API Scanner ───────────────────────────────────────────
        if run_all or "api_scanner" in checks:
            await self._run_step(session, "api_scanner", 82,
                                 self._run_api_scanner, target, session, auth_context)
            result.modules_run.append("api_scanner")

        # ── Step 8: JS Analyzer ───────────────────────────────────────────
        if run_all or "js_analyzer" in checks:
            await self._run_step(session, "js_analyzer", 90,
                                 self._run_js_analyzer, sitemap, session)
            result.modules_run.append("js_analyzer")

        # ── Step 9: ORM Hunter ────────────────────────────────────────────
        if run_all or "orm_hunter" in checks:
            await self._run_step(session, "orm_hunter", 95,
                                 self._run_orm_hunter, sitemap, session, auth_headers)
            result.modules_run.append("orm_hunter")
        
        # ── Step 10: LLM Scanner ──────────────────────────────────────────
        if run_all or "llm_scanner" in checks:
            await self._run_step(session, "llm_scanner", 98,
                                 self._run_llm_scanner, target, session, auth_headers)
            result.modules_run.append("llm_scanner")

        # ── Step 11: Race Tester ──────────────────────────────────────────
        if run_all or "race_tester" in checks:
            await self._run_step(session, "race_tester", 99,
                                 self._run_race_tester, target, session, auth_headers)
            result.modules_run.append("race_tester")

        # ── Finalize ──────────────────────────────────────────────────────
        result.scan_duration = time.monotonic() - start
        findings = session.db_session.execute(
            "SELECT severity, module FROM findings WHERE session_id = ?",
            (session.id,),
        ).fetchall() if hasattr(session.db_session, "execute") else []

        # Re-count from DB
        from medusa.engine.core.models import FindingModel
        all_findings = session.db_session.query(FindingModel).filter_by(session_id=session.id).all()
        result.total_findings = len(all_findings)
        for f in all_findings:
            sev = str(f.severity or "info")
            result.by_severity[sev] = result.by_severity.get(sev, 0) + 1
            cat = (f.module or "other").split(".")[-1]
            result.by_category[cat] = result.by_category.get(cat, 0) + 1

        # Coverage score: ratio of checks run vs total possible checks
        total_possible = len(SCAN_POLICIES["deep"]["active_checks"]) + 1  # +1 for templates
        result.coverage_score = min(len(result.modules_run) / max(total_possible, 1), 1.0)

        await self.broadcaster.emit_progress(session.id, "active_scanner", 100, "done")
        await self.broadcaster.log(
            session.id, "SUCCESS",
            f"[active_scanner] Completed in {result.scan_duration:.1f}s — "
            f"{result.total_findings} findings", "active_scanner",
        )

        # Queue AI triage
        asyncio.create_task(self._run_ai_triage(all_findings, session))

        return result

    async def _run_step(
        self, session: Session, module: str, progress: int, fn: Any, *args: Any
    ) -> Any:
        """Run a step with progress reporting and error isolation."""
        await self.broadcaster.emit_progress(session.id, module, 0, "running")
        await self.broadcaster.log(session.id, "INFO", f"[{module}] Starting …", module)
        try:
            result = await fn(*args)
            await self.broadcaster.emit_progress(session.id, module, 100, "done")
            await self.broadcaster.emit_progress(session.id, "active_scanner", progress, "running")
            return result
        except Exception as exc:
            logger.error("[%s] Error: %s", module, exc)
            await self.broadcaster.log(session.id, "ERROR", f"[{module}] Error: {exc}", module)
            await self.broadcaster.emit_progress(session.id, module, 100, "error")
            return None

    # ── Module runners ─────────────────────────────────────────────────────

    async def _run_header_analyzer(
        self, target: str, session: Session, auth_headers: dict[str, str]
    ) -> None:
        from medusa.engine.modules.web.header_analyzer import HeaderAnalyzer
        ha = HeaderAnalyzer(self.guard, self.bucket)
        await ha.run(target, session, auth_headers=auth_headers)

    async def _run_waf_detector(
        self, target: str, session: Session, auth_headers: dict[str, str]
    ) -> dict[str, Any]:
        from medusa.engine.modules.web.waf_detector import WAFDetector
        wd = WAFDetector(self.guard, self.bucket)
        return await wd.detect(target, session)

    async def _run_crawler(self, target: str, session: Session) -> Any:
        from medusa.engine.modules.web.crawler import Crawler
        c = Crawler(self.guard, self.bucket, max_depth=3)
        return await c.run(target, session)

    async def _run_template_engine(
        self,
        target: str,
        session: Session,
        categories: list[str] | None,
        severities: list[str],
        auth_headers: dict[str, str],
    ) -> list[Any]:
        from medusa.engine.modules.web.template_engine import TemplateEngine
        te = TemplateEngine(self.broadcaster)
        return await te.run(
            target, session,
            categories=categories,
            severities=severities,
            auth_headers=auth_headers,
        )

    async def _run_injectors(
        self,
        sitemap: Any,
        session: Session,
        auth_headers: dict[str, str],
        auth_cookies: dict[str, str],
    ) -> None:
        from medusa.engine.modules.web.injectors import Injectors
        inj = Injectors(self.guard, self.bucket)
        await inj.run_full(sitemap, session, auth_headers=auth_headers, auth_cookies=auth_cookies)

    async def _run_auth_tester(
        self, target: str, session: Session, auth_headers: dict[str, str]
    ) -> None:
        from medusa.engine.modules.web.auth_tester import AuthTester
        at = AuthTester(self.guard, self.bucket)
        await at.run(target, session, auth_headers=auth_headers)

    async def _run_api_scanner(
        self, target: str, session: Session, auth_context: AuthContext | None
    ) -> None:
        from medusa.engine.modules.web.api_scanner import APIScanner
        scanner = APIScanner(self.guard, self.bucket, self.broadcaster)
        await scanner.scan_rest(target, spec=None, auth_context=auth_context, session=session)
        await scanner.scan_graphql(f"{target.rstrip('/')}/graphql", auth_context=auth_context, session=session)

    async def _run_js_analyzer(self, sitemap: Any, session: Session) -> None:
        from medusa.engine.modules.web.js_analyzer import JSAnalyzer
        ja = JSAnalyzer(self.guard, self.bucket)
        await ja.run(sitemap, session)

    async def _run_orm_hunter(
        self, sitemap: Any, session: Session, auth_headers: dict[str, str]
    ) -> None:
        from medusa.engine.modules.web.orm_hunter import ORMHunter
        oh = ORMHunter(self.guard, self.bucket)
        await oh.run(sitemap, session)

    async def _run_llm_scanner(
        self, target: str, session: Session, auth_headers: dict[str, str]
    ) -> None:
        from medusa.engine.modules.web.llm_scanner import LLMScanner
        ls = LLMScanner(self.bucket)
        await ls.run(target, session, auth_context=auth_headers)

    async def _run_race_tester(
        self, target: str, session: Session, auth_headers: dict[str, str]
    ) -> None:
        from medusa.engine.modules.web.race_tester import RaceTester
        rt = RaceTester(self.bucket)
        await rt.probe_common(target, session, auth_context=auth_headers)

    async def _run_ai_triage(self, findings: list[Any], session: Session) -> None:
        try:
            from medusa.engine.modules.ai.triage import AITriage
            triage = AITriage()
            await triage.run(findings, session)
        except Exception as exc:
            logger.warning("AI triage error: %s", exc)
        try:
            from medusa.engine.modules.ai.chain_builder import suggest_chains
            await suggest_chains(session)
        except Exception as exc:
            logger.warning("Chain builder error: %s", exc)
