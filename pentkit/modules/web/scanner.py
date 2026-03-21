from __future__ import annotations
import asyncio
import httpx
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional, Literal, Any
from pentkit.core.session import Session
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import TokenBucket
from pentkit.core.scope_guard import ScopeGuard
from pentkit.core.ai_engine import AIEngine
from pentkit.modules.web.crawler import SiteMap
from pentkit.payloads.corpus_builder import CorpusBuilder
from pentkit.modules.web.waf_bypass import WAFBypassEngine, WAFProfile

logger = get_module_logger("web.scanner")

class WebScanner:
    """Active vulnerability scanner for web targets."""
    
    def __init__(self, guard: ScopeGuard, bucket: TokenBucket, ai: AIEngine):
        self.guard = guard
        self.bucket = bucket
        self.ai = ai
        self.corpus = CorpusBuilder()
        self.waf_engine = WAFBypassEngine(ai)
        self.payload_dir = Path("pentkit/payloads/web")
        self.categories = [p.stem for p in self.payload_dir.glob("*.yaml")]

    async def _analyze_finding_with_ai(self, finding_data: dict) -> dict:
        """Use AI to explain and provide remediation for a finding."""
        system = "You are a senior ethical hacker. Analyze the following vulnerability finding and provide a concise explanation and remediation."
        user = f"Finding: {finding_data['title']}\nModule: {finding_data['module']}\nTarget: {finding_data['target']}\nPayload: {finding_data['payload']}\nResponse: {finding_data['response']}"
        
        try:
            # We want a structured response
            class AIAnalysis(BaseModel):
                explanation: str
                remediation: str

            analysis = await self.ai.complete(system, user, schema=AIAnalysis)
            return analysis.model_dump()
        except Exception:
            return {"explanation": "AI analysis unavailable", "remediation": "Check standard OWASP guides."}

    async def run(self, sitemap: SiteMap, session: Session):
        """Execute vulnerability tests against discovered endpoints."""
        logger.info(f"Scanning {len(sitemap.endpoints)} endpoints for vulnerabilities", extra={"target": sitemap.target})
        
        # Detect WAF once for the target
        waf = await self.waf_engine.detect_waf(sitemap.target)
        if waf.detected:
            logger.info(f"WAF Detected: {waf.vendor} (confidence: {waf.confidence})")
        
        tasks = []
        for url in sitemap.endpoints:
            if not self.guard.is_safe(url):
                continue
                
            parsed = httpx.URL(url)
            for param in parsed.params:
                for category in self.categories:
                    # GAP 1: Use CorpusBuilder instead of static YAML
                    payloads = self.corpus.get_payloads(category, waf_vendor=waf.vendor if waf.detected else None)
                    for p in payloads:
                        tasks.append(self._test_param(url, 'get', param, p, session, waf))

        for form in sitemap.forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'search', 'email', 'url', 'password']:
                    for category in self.categories:
                        payloads = self.corpus.get_payloads(category, waf_vendor=waf.vendor if waf.detected else None)
                        for p in payloads:
                            tasks.append(self._test_param(form['action'], form['method'].lower(), input_field['name'], p, session, waf))

        if tasks:
            batch_size = 20
            for i in range(0, len(tasks), batch_size):
                await asyncio.gather(*tasks[i:i+batch_size])

    async def _test_param(self, url: str, method: str, param_name: str, payload_obj: Any, session: Session, waf: WAFProfile):
        """Test a single parameter with a payload object from corpus."""
        payload = payload_obj.payload
        payload_id = payload_obj.id
        
        async with self.bucket:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                try:
                    start_time = time.monotonic()
                    if method == 'get':
                        response = await client.get(url, params={param_name: payload})
                    else:
                        response = await client.post(url, data={param_name: payload})
                    duration = time.monotonic() - start_time
                    
                    # WAF Detection in response
                    if response.status_code in [403, 406, 419] and waf.detected:
                        # GAP 5: WAF Blocked - start bypass loop
                        logger.info(f"Payload {payload_id} blocked by {waf.vendor}. Starting bypass loop.")
                        self.corpus.record_block(payload_id, waf.vendor)
                        
                        bypass_res = await self.waf_engine.bypass_loop(url, method.upper(), param_name, payload, waf)
                        if bypass_res.success:
                            # Bypass worked!
                            self.corpus.record_success(payload_id)
                            self.corpus.update_effectiveness(payload_id, 0.1)
                            # Re-run detection on the successful variant
                            await self._report_finding(session, f"WAF Bypass: {payload_obj.injection_type}", "web.scanner", url, bypass_res.payload, "Bypassed response", "high", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                        return

                    # 1. SQLi Detection
                    sql_errors = ["sql syntax", "mysql_fetch_array", "ora-01756", "sqlite3.OperationalError", "unclosed quotation mark"]
                    if any(err in response.text.lower() for err in sql_errors):
                        self.corpus.record_success(payload_id)
                        self.corpus.update_effectiveness(payload_id, 0.15)
                        await self._report_finding(session, "SQL Injection (Error-based)", "web.scanner", url, payload, response.text, "high", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                        return

                    # 2. LFI Detection
                    lfi_markers = ["root:x:0:0:", "[extensions]", "[fonts]", "[mci extensions]"]
                    if any(marker in response.text for marker in lfi_markers):
                        self.corpus.record_success(payload_id)
                        self.corpus.update_effectiveness(payload_id, 0.15)
                        await self._report_finding(session, "Local File Inclusion", "web.scanner", url, payload, response.text, "high", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
                        return

                    # 3. RCE Detection
                    rce_markers = ["uid=0(root)", "uid=", "groups=", "Windows IP Configuration"]
                    if any(marker in response.text for marker in rce_markers):
                        self.corpus.record_success(payload_id)
                        self.corpus.update_effectiveness(payload_id, 0.2)
                        await self._report_finding(session, "Remote Code Execution", "web.scanner", url, payload, response.text, "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
                        return
                    
                    # 4. XSS Detection
                    if payload in response.text:
                        self.corpus.record_success(payload_id)
                        self.corpus.update_effectiveness(payload_id, 0.1)
                        await self._report_finding(session, "Cross-Site Scripting (Reflected)", "web.scanner", url, payload, response.text, "medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")
                        return

                    # 5. Time-based SQLi
                    if "sleep" in payload.lower() and duration > 4.5:
                        self.corpus.record_success(payload_id)
                        self.corpus.update_effectiveness(payload_id, 0.15)
                        await self._report_finding(session, "SQL Injection (Time-based)", "web.scanner", url, payload, f"Response delayed: {duration:.2f}s", "high", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                        return

                except Exception as e:
                    logger.debug(f"Error testing {url} param {param_name}: {e}" )

    async def _report_finding(self, session: Session, title: str, module: str, target: str, payload: str, response_text: str, severity: str, cvss: str):
        """Helper to create finding and enrich with AI."""
        # Truncate response for AI analysis
        truncated_res = response_text[:1000]
        
        analysis = await self._analyze_finding_with_ai({
            "title": title, "module": module, "target": target, "payload": payload, "response": truncated_res
        })

        finding = session.add_finding(
            module=module,
            target=target,
            title=title,
            description=analysis["explanation"],
            severity=severity,
            cvss_vector=cvss,
            payload=payload,
            response=response_text,
            tags=["automated", "active"]
        )
        # Update finding with remediation
        # Since session.add_finding returns the model, we can update it directly
        finding.ai_remediation = analysis["remediation"]
        session.db_session.commit()

__all__ = ["WebScanner"]
