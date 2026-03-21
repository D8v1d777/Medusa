from __future__ import annotations
import asyncio
import statistics
import time
from dataclasses import dataclass
from typing import List, Optional, Literal
import httpx
from pentkit.core.logger import get_module_logger

logger = get_module_logger("web.timing_oracle")

@dataclass
class BaselineStats:
    mean_ms: float
    std_dev_ms: float
    p95_ms: float
    p99_ms: float
    sample_size: int

class TimingResult(BaseModel):
    triggered: bool
    median_ms: float
    confidence: float
    notes: str

class TimingOracle:
    """
    Statistical approach to blind timing attacks.
    Never makes a decision from a single request. Always uses hypothesis testing.
    """

    async def calibrate(self, url: str, param: str, n: int = 20) -> Optional[BaselineStats]:
        """
        Send n legitimate requests. Record response times.
        Compute: mean, std_dev, p95, p99.
        """
        logger.info(f"Calibrating timing baseline for {url}", extra={"target": url})
        times = []
        
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            for i in range(n):
                # Use different parameter values each time to avoid caching
                val = f"PENTKIT_CALIB_{int(time.time())}_{i}"
                try:
                    start = time.perf_counter()
                    await client.get(url, params={param: val})
                    end = time.perf_counter()
                    times.append((end - start) * 1000)
                    # Random jitter between requests
                    await asyncio.sleep(0.1 + (0.4 * (i % 5) / 5))
                except Exception as e:
                    logger.debug(f"Calibration request failed: {e}")

        if not times:
            return None

        mean = statistics.mean(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        sorted_times = sorted(times)
        p95 = sorted_times[int(len(times) * 0.95)]
        p99 = sorted_times[int(len(times) * 0.99)] if len(times) > 1 else p95

        if p99 > 3000:
            logger.warning(f"Target {url} too slow for timing attacks (p99={p99:.0f}ms). Skipping.")
            return None

        return BaselineStats(mean, std_dev, p95, p99, len(times))

    async def test(
        self,
        url: str,
        method: Literal["GET", "POST"],
        param: str,
        payload: str,
        baseline: BaselineStats,
        sleep_duration: int = 5,
        trials: int = 5,
    ) -> TimingResult:
        """
        Statistical hypothesis test for time-based blind SQLi.
        """
        payload_times = []
        
        async with httpx.AsyncClient(verify=False, timeout=sleep_duration + 10.0) as client:
            for i in range(trials):
                # Randomise sleep duration slightly per trial to avoid signatures
                actual_sleep = sleep_duration + (i % 3 - 1)
                # Replace placeholder in payload if needed
                current_payload = payload.replace("SLEEP_DUR", str(actual_sleep))
                
                try:
                    start = time.perf_counter()
                    if method == "GET":
                        await client.get(url, params={param: current_payload})
                    else:
                        await client.post(url, data={param: current_payload})
                    end = time.perf_counter()
                    payload_times.append((end - start) * 1000)
                    # Jitter between trials
                    await asyncio.sleep(2 + (3 * (i % 5) / 5))
                except Exception as e:
                    logger.debug(f"Timing trial failed: {e}")

        if not payload_times:
            return TimingResult(triggered=False, median_ms=0, confidence=0, notes="All trials failed")

        median_payload = statistics.median(payload_times)
        std_dev_payload = statistics.stdev(payload_times) if len(payload_times) > 1 else 0
        
        # Decision rule from spec
        triggered = (
            median_payload > baseline.mean + (sleep_duration * 1000 * 0.8) and
            min(payload_times) > baseline.p95 and
            std_dev_payload < (sleep_duration * 1000 * 0.5)
        )

        confidence = 0.0
        if triggered:
            # Simple confidence metric
            confidence = min(1.0, (median_payload - baseline.mean) / (sleep_duration * 1000))
        
        return TimingResult(
            triggered=triggered,
            median_ms=median_payload,
            confidence=confidence,
            notes=f"Baseline mean={baseline.mean:.0f}ms, Median payload={median_payload:.0f}ms"
        )

    def select_sleep(self, baseline: BaselineStats) -> int:
        """Select sleep duration based on baseline noise."""
        if baseline.std_dev_ms < 100: return 3
        if baseline.std_dev_ms < 500: return 5
        if baseline.std_dev_ms < 1000: return 8
        return 0 # Skip

from pydantic import BaseModel
__all__ = ["TimingOracle", "BaselineStats", "TimingResult"]
