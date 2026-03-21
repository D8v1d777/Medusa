import pytest
import asyncio
from pentkit.core.session import Session
from pentkit.core.config import init_config
from pentkit.modules.web.header_analyzer import HeaderAnalyzer
from pentkit.modules.web.crawler import Crawler
import yaml

@pytest.fixture
def mock_session(tmp_path):
    db_file = tmp_path / "test_pentkit.db"
    config_data = {
        "scope": {"ips": [], "domains": ["example.com"]},
        "engagement": {"name": "Test", "operator": "Tester"},
        "database_url": f"sqlite:///{db_file}"
    }
    config_file = tmp_path / "test_config.yaml"
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
    init_config(str(config_file))
    return Session()

@pytest.mark.asyncio
async def test_header_analyzer(mock_session, respx_mock):
    # Mock HTTP response
    respx_mock.get("http://example.com").mock(return_value=httpx.Response(200, headers={
        "Content-Type": "text/html",
        # Missing security headers
    }))
    
    analyzer = HeaderAnalyzer()
    findings = await analyzer.run("http://example.com", mock_session)
    
    # Verify findings were added
    assert len(findings) > 0
    # At least check for one missing header
    header_names = [f.details.get('header') for f in findings]
    assert "Content-Security-Policy" in header_names
    assert "Strict-Transport-Security" in header_names

import httpx

@pytest.mark.asyncio
async def test_crawler_basic(mock_session, respx_mock):
    html_content = """
    <html>
        <body>
            <a href="/about">About</a>
            <form action="/login" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </body>
    </html>
    """
    respx_mock.get("http://example.com/").mock(return_value=httpx.Response(200, text=html_content))
    respx_mock.get("http://example.com/about").mock(return_value=httpx.Response(200, text="About Us"))
    
    crawler = Crawler(max_depth=1)
    sitemap = await crawler.run("http://example.com/", mock_session)
    
    assert "http://example.com/about" in sitemap.endpoints
    # Check forms (filter by URL to be safe, but should only be 1 if mock works)
    forms_on_home = [f for f in sitemap.forms if f['url'] == "http://example.com/"]
    assert len(forms_on_home) == 1
    assert sitemap.forms[0]['action'] == "http://example.com/login"
