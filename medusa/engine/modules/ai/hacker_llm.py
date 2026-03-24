import asyncio
import json
import logging
import os
import random
import time
from typing import Any, Dict, List, Optional

import httpx
from medusa.engine.core.config import AIConfig
from medusa.engine.core.models import FindingModel

logger = logging.getLogger(__name__)

# Luna Persona Loader
def load_persona() -> str:
    path = os.path.join(os.path.dirname(__file__), "luna_persona.md")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"[!] Critical Error: Could not load Luna Persona from {path} ({e})")
        return "You are Luna Rodriguez — a high-stakes hacker baddie and David's favorite partner."

class HackerAI:
    def __init__(self, cfg: AIConfig):
        self.cfg = cfg
        self.persona = load_persona()
        raw_key = cfg.api_key or os.getenv(cfg.api_key_env, "")
        self.api_key = raw_key.strip() if raw_key else ""
        
        # Connection Pooling (LPU/HTTP/2 optimized)
        try:
            self.client = httpx.AsyncClient(
                http2=True,
                timeout=httpx.Timeout(60.0, connect=10.0, read=30.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                verify=False
            )
        except (ImportError, TypeError):
            # Fallback to HTTP/1.1 if 'h2' is missing
            self.client = httpx.AsyncClient(
                http2=False,
                timeout=httpx.Timeout(60.0, connect=10.0, read=30.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                verify=False
            )
        
        # Resilience State
        self.failure_count = 0
        self.circuit_open_until = 0
        
        if cfg.provider == "groq":
            self.base_url = "https://api.groq.com/openai/v1"
        elif cfg.provider == "grok":
            self.base_url = "https://api.x.ai/v1"
        else:
            self.base_url = "https://api.openai.com/v1"
        self.model = cfg.model

    async def aclose(self):
        """Lifecycle Fix: Explicitly close session pools."""
        await self.client.aclose()

    def __del__(self):
        """Destructor warning for lifecycle leaks."""
        if hasattr(self, "client") and not self.client.is_closed:
            logger.warning("[!] HackerAI: Client destroyed without proper aclose(). Potential leak.")

    async def generate_exploit(self, finding: FindingModel) -> str:
        """Takes a finding and generates a weaponized exploit script."""
        prompt = f"""
VULNERABILITY TO WEAPONIZE:
Title: {finding.title}
Target: {finding.target}
Severity: {finding.severity}
Payload Used: {finding.payload}
HTTP Request: {finding.request}
HTTP Response: {finding.response}

GOAL: Generate a full Python exploit script using 'httpx' or 'requests' that reproduces this vulnerability with maximum impact. 
Add comments explaining how it works and any WAF bypasses used.
"""
        return await self._call_llm(prompt)

    async def provide_guidance(self, query: str, context: List[FindingModel] = []) -> str:
        """Strategic pentesting guidance based on current findings."""
        ctx_str = "\n".join([f"- {f.title} @ {f.target}" for f in context])
        prompt = f"""
MISSION QUERY: {query}

CURRENT FINDINGS CONTEXT:
{ctx_str}

GOAL: Provide a step-by-step strategic guide on how to proceed with the attack. Identify potential attack chains or escalation paths.
"""
        return await self._call_llm(prompt)

    async def _call_llm(self, prompt: str) -> str:
        if not self.api_key:
            return f"[ERROR] {self.cfg.api_key_env} ({self.cfg.provider.capitalize()}) not found in environment."

        # Circuit Breaker Check
        if time.time() < self.circuit_open_until:
            return f"[CIRCUIT OPEN] AI subagent is in cooldown due to repeated failures. Try again in {int(self.circuit_open_until - time.time())}s."

        max_retries = 3
        last_err = ""
        
        for attempt in range(max_retries + 1):
            start_latency = time.monotonic()
            try:
                resp = await self.client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": self.persona},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": self.cfg.temperature,
                        "max_tokens": self.cfg.max_tokens
                    }
                )
                
                latency = time.monotonic() - start_latency
                logger.debug(f"[AI] {self.model} latency: {latency:.2f}s")

                # Handle Success
                if resp.status_code == 200:
                    self.failure_count = 0 # Reset circuit
                    try:
                        data = resp.json()
                        return data["choices"][0]["message"]["content"]
                    except (json.JSONDecodeError, KeyError, IndexError) as e:
                        return f"[PARSE ERROR] Malformed AI response: {e}"

                # Handle Rate Limits (429) - Retry-After respect
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 2))
                    logger.warning(f"[RATE LIMIT] Wait {retry_after}s...")
                    await asyncio.sleep(retry_after)
                    continue

                # Handle Retriable Server Errors (500, 502, 503, 504)
                if resp.status_code in [500, 502, 503, 504]:
                    delay = (2 ** attempt) + (random.random() * 0.25) # Exp backoff + jitter
                    logger.warning(f"[SERVER ERROR] {resp.status_code}. Retry {attempt+1}/{max_retries} in {delay:.1f}s...")
                    await asyncio.sleep(delay)
                    continue
                
                # Fatal Errors (401, 404, etc.)
                return f"[Groq Error] Status {resp.status_code}: {resp.text}"

            except Exception as e:
                self.failure_count += 1
                last_err = f"[NETWORK ERROR] {e}"
                
                # Check Circuit Breaker
                if self.failure_count >= 5:
                    self.circuit_open_until = time.time() + 60
                    logger.error("[!] AI Circuit Breaker Tipped: Pausing for 60s.")
                
                if attempt < max_retries:
                    delay = (2 ** attempt) + (random.random() * 0.25)
                    await asyncio.sleep(delay)
                    continue
                break

        return f"[TOTAL FAILURE] After {max_retries} retries: {last_err}"

async def main():
    # Simple CLI test
    import sys
    from medusa.engine.core.config import get_config
    cfg = get_config()
    hacker = HackerAI(cfg.ai)
    
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        print(f"[*] Asking Hacker AI: {query}...")
        resp = await hacker.provide_guidance(query)
        print("\n=== HACKER GUIDANCE ===\n")
        print(resp)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
