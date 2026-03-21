from __future__ import annotations
import asyncio
import time
from typing import Dict, Literal
from pentkit.core.config import Config

class TokenBucket:
    """Async token bucket for rate limiting."""
    
    def __init__(self, rate: float):
        self.rate = rate  # Tokens per second
        self.capacity = max(1.0, rate)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()

    async def _add_tokens(self):
        now = time.monotonic()
        delta = now - self.last_update
        new_tokens = delta * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_update = now

    async def acquire(self):
        """Acquire a token, wait if necessary."""
        async with self.lock:
            while self.tokens < 1:
                await self._add_tokens()
                if self.tokens < 1:
                    wait_time = (1 - self.tokens) / self.rate
                    await asyncio.sleep(wait_time)
            self.tokens -= 1

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

class RateLimiter:
    """Orchestrates token buckets for different modules."""
    
    def __init__(self, cfg: Config):
        self.buckets = {
            "web": TokenBucket(cfg.rates.web),
            "network": TokenBucket(cfg.rates.network),
            "redteam": TokenBucket(cfg.rates.redteam)
        }
        self.request_counts: dict[str, int] = {
            "web": 0,
            "network": 0,
            "redteam": 0
        }

    def acquire(self, module_type: Literal["web", "network", "redteam"]) -> TokenBucket:
        """Get the token bucket for a specific module type."""
        self.request_counts[module_type] += 1
        return self.buckets[module_type]

__all__ = ["RateLimiter", "TokenBucket"]
