"""Integration test for web module against DVWA."""
import pytest


from medusa.engine.core.config import Config
from medusa.engine.core.session import Session
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.rate_limiter import RateLimiter
from medusa.engine.modules.web.header_analyzer import HeaderAnalyzer


DVWA_URL = "http://localhost:4280"
pytestmark = pytest.mark.skipif(
    True,  # Skip unless DVWA is running; set to False when testing with Docker
    reason="DVWA not running; start with docker-compose up -d",
)


@pytest.mark.asyncio
async def test_header_analyzer_dvwa():
    """Test header analyzer against DVWA."""
    cfg = Config.load()
    cfg.scope.domains = ["localhost"]
    s = Session(cfg, name="test", operator="test", scope_domains=["localhost"])
    guard = ScopeGuard(ips=["127.0.0.1"], domains=["localhost"], cidrs=["127.0.0.0/8"])
    limiter = RateLimiter(cfg)
    analyzer = HeaderAnalyzer(guard, limiter.acquire("web"))
    await analyzer.run(DVWA_URL, s)
    # Should complete without error
    assert s.model is not None
