from __future__ import annotations
import asyncio
import httpx
import json
import logging
from bs4 import BeautifulSoup
from dataclasses import dataclass, field, asdict
from typing import Set, List, Dict, Optional
from playwright.async_api import async_playwright
from pentkit.core.session import Session
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import TokenBucket
from pentkit.core.scope_guard import ScopeGuard
from urllib.parse import urljoin, urlparse

logger = get_module_logger("web.crawler")

@dataclass
class SiteMap:
    target: str
    endpoints: Set[str] = field(default_factory=set)
    forms: List[Dict] = field(default_factory=list)
    js_routes: Set[str] = field(default_factory=set)
    cookies: List[Dict] = field(default_factory=list)
    technologies: Set[str] = field(default_factory=set)

    def to_json(self):
        data = asdict(self)
        data['endpoints'] = list(self.endpoints)
        data['js_routes'] = list(self.js_routes)
        data['technologies'] = list(self.technologies)
        return json.dumps(data, indent=2)

class Crawler:
    """Async web crawler with SPA support and scope enforcement."""
    
    def __init__(self, guard: ScopeGuard, bucket: TokenBucket, max_depth: int = 3):
        self.guard = guard
        self.bucket = bucket
        self.max_depth = max_depth
        self.visited = set()
        self.sitemap = None
        self.ignored_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.mp4', '.mp3',
            '.zip', '.tar', '.gz', '.rar', '.exe', '.bin'
        }

    def _should_ignore(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.ignored_extensions)

    def _is_spa(self, html: str) -> bool:
        markers = ['react', 'vue', 'angular', '_next', 'svelte']
        html_lower = html.lower()
        return any(marker in html_lower for marker in markers)

    async def _extract_info(self, url: str, html: str):
        soup = BeautifulSoup(html, 'html.parser')
        
        # Endpoints
        for a in soup.find_all('a', href=True):
            full_url = urljoin(url, a['href'])
            # Only add if in scope and not ignored
            if self.guard.is_safe(full_url):
                clean_url = full_url.split('#')[0]
                if not self._should_ignore(clean_url):
                    self.sitemap.endpoints.add(clean_url)

        # Forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value')
                })
            self.sitemap.forms.append({
                'url': url,
                'action': urljoin(url, action),
                'method': method,
                'inputs': inputs
            })

    async def _crawl_playwright(self, url: str):
        """Fallback to Playwright for SPA detection and content capture."""
        logger.info(f"Falling back to Playwright for SPA: {url}", extra={"pentkit_module": "web.crawler", "target": url})
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            try:
                await page.goto(url, timeout=30000)
                await page.wait_for_load_state('networkidle', timeout=30000)
                html = await page.content()
                
                # Check for dynamic routes in scripts (concise)
                # In a real implementation, we would use page.on("request") to capture all calls
                return html
            except Exception as e:
                logger.error(f"Playwright error for {url}: {e}", extra={"pentkit_module": "web.crawler", "target": url})
                return ""
            finally:
                await browser.close()

    async def run(self, target: str, session: Session) -> SiteMap:
        """Execute the crawl starting from target URL."""
        self.guard.check(target, "web.crawler")
        
        self.sitemap = SiteMap(target=target)
        self.sitemap.endpoints.add(target)
        
        queue = [(target, 0)]
        while queue:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue
            
            self.visited.add(url)
            logger.info(f"Crawling {url} (depth {depth})", extra={"target": url})

            async with self.bucket:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10.0) as client:
                    try:
                        response = await client.get(url)
                        content_type = response.headers.get('Content-Type', '').lower()
                        
                        if 'text/html' not in content_type:
                            continue

                        html = response.text
                        if self._is_spa(html):
                            html = await self._crawl_playwright(url)
                        
                        if html:
                            await self._extract_info(url, html)
                        
                        # Add newly discovered endpoints to queue
                        for endpoint in self.sitemap.endpoints:
                            if endpoint not in self.visited:
                                queue.append((endpoint, depth + 1))

                    except Exception as e:
                        logger.error(f"Error crawling {url}: {e}", extra={"target": url})

        return self.sitemap

__all__ = ["Crawler", "SiteMap"]
