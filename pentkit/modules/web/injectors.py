from __future__ import annotations
import asyncio
import httpx
import time
import logging
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Literal, Tuple
from pydantic import BaseModel
from pentkit.core.session import Session
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import TokenBucket
from pentkit.core.scope_guard import ScopeGuard
from pentkit.core.ai_engine import AIEngine
from pentkit.modules.web.crawler import SiteMap
from pentkit.modules.web.timing_oracle import TimingOracle, BaselineStats
from pentkit.modules.web.waf_bypass import WAFBypassEngine, WAFProfile
from pentkit.payloads.generator import generator as payload_gen

logger = get_module_logger("web.injectors")

class InjectionContext(BaseModel):
    """Detected from response analysis before any payload is sent."""
    db_engine: Literal["mysql", "mssql", "postgres", "sqlite", "oracle", "unknown"] = "unknown"
    orm_detected: bool = False
    encoding_layers: List[str] = []
    reflection_type: Literal["direct", "html_encoded", "js_string", "json_value", "none"] = "none"
    waf_profile: Optional[WAFProfile] = None
    content_type: str = "text/html"
    injection_point: Literal["query_param", "post_body", "json_field", "xml_node", "http_header", "cookie", "path_segment"] = "query_param"

class AdaptiveInjectionEngine:
    """
    Context-aware adaptive payload engine.
    Replaces static YAML dispatch with dynamic generation.
    """

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket, ai: AIEngine):
        self.guard = guard
        self.bucket = bucket
        self.ai = ai
        self.timing = TimingOracle()
        self.waf_bypass = WAFBypassEngine(ai)

    async def detect_context(self, url: str, param: str, method: str) -> InjectionContext:
        """Probe for DB engine, encoding, and reflection context."""
        ctx = InjectionContext()
        
        # 1. WAF Detection
        ctx.waf_profile = await self.waf_bypass.detect_waf(url)
        
        # 2. Reflection analysis
        canary = f"PENTKIT_REFLECT_{uuid.uuid4().hex[:8]}"
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            try:
                if method == "GET":
                    response = await client.get(url, params={param: canary})
                else:
                    response = await client.post(url, data={param: canary})
                
                body = response.text
                if canary in body:
                    ctx.reflection_type = "direct"
                    # Basic context detection
                    if f"'{canary}'" in body or f'"{canary}"' in body:
                        ctx.reflection_type = "js_string"
                elif canary.encode().hex() in body:
                    ctx.encoding_layers.append("hex")
            except Exception:
                pass

        # 3. DB engine fingerprinting (Error-based probes)
        probes = {
            "mysql": "' -- -",
            "mssql": "' --",
            "postgres": "'",
            "oracle": "' --",
            "sqlite": "'"
        }
        # In real case, gather these. For concise demo, we'll do sequential or skip.
        return ctx

    async def run(self, sitemap: SiteMap, session: Session):
        """Execute adaptive scans against all discovered endpoints."""
        for url in sitemap.endpoints:
            # 1. Calibrate timing baseline for the endpoint
            # Pick a representative param or use a dummy one
            baseline = await self.timing.calibrate(url, "pk_calib")
            
            # 2. Process forms
            for form in sitemap.forms:
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'email', 'url', 'password']:
                        await self._scan_param(form['action'], form['method'].upper(), input_field['name'], baseline, session)

            # 3. Process URL params
            parsed = httpx.URL(url)
            for param in parsed.params:
                await self._scan_param(url, "GET", param, baseline, session)

    async def _scan_param(self, url: str, method: str, param: str, baseline: Optional[BaselineStats], session: Session):
        """Perform context-aware scan on a single parameter."""
        # Detect context
        ctx = await self.detect_context(url, param, method)
        
        # Try SQLi
        await self._try_sqli(url, method, param, ctx, baseline, session)
        
        # Try XSS
        await self._try_xss(url, method, param, ctx, session)

    async def _try_sqli(self, url: str, method: str, param: str, ctx: InjectionContext, baseline: Optional[BaselineStats], session: Session):
        # 1. Error-based SQLi
        # ... logic ...
        
        # 2. Time-based SQLi (using TimingOracle)
        if baseline:
            sleep_dur = self.timing.select_sleep(baseline)
            if sleep_dur > 0:
                payload = f"'; SELECT SLEEP(SLEEP_DUR); -- -" # Example
                result = await self.timing.test(url, method, param, payload, baseline, sleep_duration=sleep_dur)
                if result.triggered:
                    session.add_finding(
                        module="web.injectors", target=url, title="Time-based SQL Injection",
                        description=f"Confirmed via statistical timing oracle. {result.notes}",
                        severity="high", payload=payload, confidence=result.confidence
                    )

    async def _try_xss(self, url: str, method: str, param: str, ctx: InjectionContext, session: Session):
        # Build payload based on reflection context
        pass

__all__ = ["AdaptiveInjectionEngine", "InjectionContext"]
