from __future__ import annotations
import logging
from typing import List, Optional
from pentkit.core import Session, RateLimiter, AIEngine, ScopeGuard
from pentkit.core.logger import get_module_logger
from pentkit.modules.web.header_analyzer import HeaderAnalyzer
from pentkit.modules.web.crawler import Crawler, SiteMap
from pentkit.modules.web.scanner import WebScanner
from pentkit.modules.web.orm_hunter import ORMRawQueryHunter
from pentkit.modules.web.verifier import FindingVerifier
from pentkit.modules.web.api_fuzzer import APIFuzzer

logger = get_module_logger("web")

class WebModule:
    """Orchestrator for the Web Application Pentesting module."""
    
    def __init__(self, guard: ScopeGuard, limiter: RateLimiter, ai: AIEngine):
        self.guard = guard
        self.limiter = limiter
        self.ai = ai
        
        # Initialize sub-modules
        web_bucket = limiter.acquire("web")
        self.header_analyzer = HeaderAnalyzer(web_bucket)
        self.crawler = Crawler(guard, web_bucket, max_depth=3)
        self.scanner = WebScanner(guard, web_bucket, ai)
        self.orm_hunter = ORMRawQueryHunter(guard, web_bucket, ai)
        self.verifier = FindingVerifier()
        self.api_fuzzer = APIFuzzer(web_bucket, ai)

    async def run(self, target: str, session: Session):
        """Run all web pentesting components in sequence."""
        logger.info(f"Starting Web Module scan: {target}", extra={"target": target})
        
        # 1. Passive Header Analysis
        await self.header_analyzer.run(target, session)
        
        # 2. Discovery (Crawling)
        sitemap = await self.crawler.run(target, session)
        logger.info(f"Crawl complete. Discovered {len(sitemap.endpoints)} endpoints.", extra={"target": target})
        
        # 3. Active Scanning (Injection, etc.)
        await self.scanner.run(sitemap, session)

        # 4. ORM Raw Query Hunting (Precision GAP 2)
        await self.orm_hunter.run(sitemap, session)
        
        # 5. Mandatory Verification Pass (Precision GAP 9)
        await self.verifier.run_verification_pass(session)
        
        # 6. API Fuzzing & Discovery
        await self.api_fuzzer.run(target, session)
        
        logger.info(f"Web Module scan complete for {target}", extra={"target": target})

__all__ = ["WebModule"]
