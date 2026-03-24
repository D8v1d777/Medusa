"""
Race Condition Tester — Tactical Concurrency Exploitation.
Detects atomicity failures in sensitive transactions (transfers, checkouts, votings).
Designed for high-performance concurrent probing (v2026 standards).
"""
import asyncio
import logging
import time
from typing import Any, List

import httpx
from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.session import Session

logger = logging.getLogger(__name__)

class RaceTester:
    def __init__(self, bucket: TokenBucket):
        self.bucket = bucket

    async def run(
        self, 
        target_url: str, 
        session: Session, 
        method: str = "POST", 
        data: dict | None = None, 
        headers: dict | None = None,
        concurrency: int = 15
    ) -> None:
        """Attempts to trigger a race condition via rapid concurrent requests."""
        if "/api/" not in target_url and "transfer" not in target_url.lower() and "checkout" not in target_url.lower():
            # Skip non-transactional looking endpoints to avoid reckless scanning
            return

        logger.info(f"[*] Testing for Race Condition at: {target_url} (x{concurrency} threads)")
        
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            tasks = []
            # We bypass the normal bucket for a momentary burst to test for the race
            for _ in range(concurrency):
                tasks.append(client.request(method, target_url, json=data, headers=headers))

            # Synchronized burst execution
            start_time = time.monotonic()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            duration = time.monotonic() - start_time

            # Analyze results: If multiple 200/201 responses arrive for a single-state action, it's a finding.
            success_count = 0
            for r in responses:
                if isinstance(r, httpx.Response) and r.status_code in [200, 201]:
                    success_count += 1
            
            if success_count > 1:
                # Potential Race condition! 
                session.add_finding(
                    module="web.race_tester",
                    target=target_url,
                    title="Potential Transactional Race Condition",
                    description=(
                        f"Detected multiple success responses ({success_count}/{concurrency}) for a single-state transaction.\n"
                        f"This suggests a lack of atomicity or locking at the database level.\n"
                        f"Burst duration: {duration:.4f}s"
                    ),
                    severity="high",
                    payload=str(data),
                    exploit_poc=f"burp_intruder_turbo: {concurrency} threads to {target_url}",
                    tags=["race-condition", "broken-logic", "atomicity"],
                    owasp_category="A04:2021-Insecure Design",
                    confidence="medium"
                )

    async def probe_common(self, target: str, session: Session, auth_context: Any = None) -> None:
        """Heuristic search for race-prone endpoints."""
        common_tx = ["/api/v1/payment", "/api/v1/transfer", "/api/cart/checkout", "/api/v1/credits/redeem"]
        for path in common_tx:
            url = f"{target.rstrip('/')}{path}"
            # Test with dummy data
            await self.run(url, session, data={"amount": 0.01, "to": "self"}, headers=auth_context.headers if auth_context else None)
