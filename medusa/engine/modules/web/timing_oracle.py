"""Timing oracle — statistical blind SQLi detection."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

__all__ = ["TimingOracle", "BaselineStats"]

logger = logging.getLogger(__name__)


@dataclass
class BaselineStats:
    """Baseline response time statistics."""

    mean_ms: float
    std_dev_ms: float
    p95_ms: float
    p99_ms: float
    sample_size: int


class TimingOracle:
    """Statistical timing for blind SQLi."""

    async def calibrate(
        self, endpoint: str, param: str, n: int = 20
    ) -> BaselineStats:
        """Establish baseline response times."""
        times: list[float] = []
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            for i in range(n):
                try:
                    start = time.perf_counter()
                    await client.get(endpoint, params={param: f"baseline_{i}"})
                    times.append((time.perf_counter() - start) * 1000)
                except Exception:
                    pass
                await asyncio.sleep(0.2)
        if not times:
            return BaselineStats(0.0, 0.0, 0.0, 0.0, 0)
        times.sort()
        mean = sum(times) / len(times)
        variance = sum((t - mean) ** 2 for t in times) / len(times)
        std = variance ** 0.5
        p95 = times[int(len(times) * 0.95)] if len(times) > 1 else times[0]
        p99 = times[-1] if times else 0.0
        return BaselineStats(mean_ms=mean, std_dev_ms=std, p95_ms=p95, p99_ms=p99, sample_size=len(times))
