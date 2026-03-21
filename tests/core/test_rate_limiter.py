from __future__ import annotations
import asyncio
import time
import pytest
from pentkit.core.rate_limiter import RateLimiter
from pentkit.core.config import Config, EngagementConfig, ScopeConfig, RatesConfig

@pytest.fixture
def mock_cfg():
    return Config(
        engagement=EngagementConfig(name="Test", operator="Tester", authorized=True),
        scope=ScopeConfig(),
        rates=RatesConfig(web=10.0, network=2.0, redteam=0.5),
        database_url="sqlite:///:memory:"
    )

@pytest.mark.asyncio
async def test_rate_limiter_web(mock_cfg):
    limiter = RateLimiter(mock_cfg)
    bucket = limiter.acquire("web")
    
    start = time.monotonic()
    for _ in range(10):
        await bucket.acquire()
    end = time.monotonic()
    
    # 10 tokens at 10/s should be fast initially
    assert end - start < 0.1
    
    # Next token should wait approx 0.1s
    start = time.monotonic()
    await bucket.acquire()
    end = time.monotonic()
    assert end - start >= 0.08

def test_rate_limiter_counts(mock_cfg):
    limiter = RateLimiter(mock_cfg)
    limiter.acquire("web")
    limiter.acquire("web")
    limiter.acquire("network")
    
    assert limiter.request_counts["web"] == 2
    assert limiter.request_counts["network"] == 1
    assert limiter.request_counts["redteam"] == 0
