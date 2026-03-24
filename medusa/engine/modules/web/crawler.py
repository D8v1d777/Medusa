"""
Hybrid Web Crawler — TIER 1.
Combines fast static crawling (httpx/bs4) with dynamic AJAX crawling (Playwright).
Replaces ZAP's Standard Spider and AJAX Spider.
Feeds sitemap to ActiveScanner and Injectors.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster

__all__ = ["Crawler", "SiteMap", "Form", "Endpoint"]

logger = logging.getLogger(__name__)


@dataclass
class Endpoint:
    """Discovered API endpoint or page."""
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    src: str = "static"  # static, dynamic, js, spec
    auth_required: bool = False


@dataclass
class Form:
    """Discovered HTML form."""
    action: str
    method: str
    inputs: list[dict[str, Any]]
    id: str = ""
    name: str = ""


@dataclass
class SiteMap:
    """Comprehensive crawl result."""
    base_url: str
    endpoints: list[str] = field(default_factory=list)  # Unique URLs
    detailed_endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    api_schemas: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "endpoints": self.endpoints,
            "detailed_endpoints": [asdict(e) for e in self.detailed_endpoints],
            "forms": [asdict(f) for f in self.forms],
            "js_files": self.js_files,
            "api_schemas": self.api_schemas,
            "technologies": self.technologies,
            "cookies": self.cookies,
        }


class Crawler:
    """
    High-performance web crawler.
    - Static spider for speed.
    - AJAX spider for SPAs and JS-heavy sites.
    - API discovery for modern backends.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        broadcaster: WSBroadcaster | None = None,
        max_depth: int = 3,
        max_pages: int = 500,
        concurrency: int = 10,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.broadcaster = broadcaster or WSBroadcaster()
        self._visited: set[str] = set()
        self._ignored_ext = {
            ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".zip", ".tar.gz",
            ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".css", ".ico", ".exe",
        }

    async def run(
        self,
        target: str,
        session: Session,
        use_headless: bool = True,
    ) -> SiteMap:
        """Execute full crawl (Static + Optional Headless)."""
        await self.broadcaster.log(session.id, "INFO", f"[crawler] Starting crawl on {target}", "crawler")
        await self.broadcaster.emit_progress(session.id, "crawler", 0, "running")

        self._visited.clear()
        sitemap = SiteMap(base_url=target)

        # ── Step 1: Static Crawl ──────────────────────────────────────────
        await self._static_crawl(target, sitemap, session)

        # ── Step 2: Headless/AJAX Crawl (Optional) ────────────────────────
        if use_headless:
            await self._headless_crawl(target, sitemap, session)

        # ── Step 3: API Spec Discovery ────────────────────────────────────
        await self._api_discovery(target, sitemap, session)

        await self.broadcaster.emit_progress(session.id, "crawler", 100, "done")
        await self.broadcaster.log(
            session.id, "SUCCESS",
            f"[crawler] Complete. Found {len(sitemap.endpoints)} endpoints, {len(sitemap.forms)} forms.",
            "crawler",
        )
        return sitemap

    # ── Static Engine ────────────────────────────────────────────────────────

    async def _static_crawl(self, target: str, sitemap: SiteMap, session: Session) -> None:
        """Fast link discovery using httpx and BeautifulSoup."""
        queue: list[tuple[str, int]] = [(target, 0)]
        semaphore = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            verify=False, timeout=10.0,
            headers={"User-Agent": "Medusa-Scanner/1.0 (Spider)"},
            follow_redirects=True,
        ) as client:
            while queue and len(self._visited) < self.max_pages:
                batch = []
                while queue and len(batch) < self.concurrency:
                    batch.append(queue.pop(0))

                tasks = [self._process_url(client, url, depth, sitemap, session, queue)
                         for url, depth in batch]
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _process_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        sitemap: SiteMap,
        session: Session,
        queue: list[tuple[str, int]],
    ) -> None:
        if url in self._visited or not self.guard.is_safe(url):
            return
        self._visited.add(url)

        try:
            async with self.bucket:
                resp = await client.get(url)

            if resp.status_code != 200:
                return

            if url not in sitemap.endpoints:
                sitemap.endpoints.append(url)
                sitemap.detailed_endpoints.append(Endpoint(url=url, src="static"))

            # Parse content
            ct = resp.headers.get("Content-Type", "").lower()
            if "html" in ct:
                await self._extract_html_assets(url, resp.text, depth, sitemap, queue)
            elif "javascript" in ct or "json" in ct:
                self._extract_js_endpoints(url, resp.text, sitemap)

        except Exception as exc:
            logger.debug("Crawl error %s: %s", url, exc)

    async def _extract_html_assets(
        self, base_url: str, html: str, depth: int, sitemap: SiteMap, queue: list[tuple[str, int]]
    ) -> None:
        soup = BeautifulSoup(html, "html.parser")

        # Links
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            full = urljoin(base_url, str(href)).split("#")[0].rstrip("/")
            if self.guard.is_safe(full) and not self._is_binary(full):
                if full not in sitemap.endpoints:
                    sitemap.endpoints.append(full)
                    if depth < self.max_depth:
                        queue.append((full, depth + 1))

        # Forms
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
            sitemap.forms.append(Form(
                action=urljoin(base_url, action),
                method=method,
                inputs=inputs,
                id=form.get("id", ""),
                name=form.get("name", ""),
            ))

        # JS Files
        for script in soup.find_all("script", src=True):
            src = script.get("src")
            full_js = urljoin(base_url, str(src))
            if full_js not in sitemap.js_files:
                sitemap.js_files.append(full_js)

    # ── Headless Engine ──────────────────────────────────────────────────────

    async def _headless_crawl(self, target: str, sitemap: SiteMap, session: Session) -> None:
        """Dynamic discovery for SPAs (React, Vue, Angular)."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("playwright not installed — skipping AJAX crawl")
            return

        await self.broadcaster.log(session.id, "INFO", "[crawler] Starting AJAX spider (headless)", "crawler")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            # Listen for network requests to catch API calls
            async def _handle_request(req: Any) -> None:
                u = req.url
                if self.guard.is_safe(u) and u not in sitemap.endpoints:
                    sitemap.endpoints.append(u)
                    sitemap.detailed_endpoints.append(Endpoint(url=u, method=req.method, src="dynamic"))

            page.on("request", _handle_request)

            try:
                await page.goto(target, wait_until="networkidle", timeout=30000)
                # Scroll to trigger lazy loads
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(2)

                # Extract buttons/links that only exist in DOM
                links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a, button, [onclick]'))
                        .map(el => el.href || el.getAttribute('onclick') || '')
                        .filter(v => v.length > 0)
                """)
                for link in links:
                    if link.startswith("http"):
                        full = link.split("#")[0]
                        if self.guard.is_safe(full) and full not in sitemap.endpoints:
                            sitemap.endpoints.append(full)
            except Exception as exc:
                logger.debug("Headless crawl error: %s", exc)
            finally:
                await browser.close()

    # ── Logic ────────────────────────────────────────────────────────────────

    def _extract_js_endpoints(self, base_url: str, content: str, sitemap: SiteMap) -> None:
        """Extract URLs from JS strings using regex."""
        # Regex for path-like strings
        patterns = [
            r'[\'"](/api/v[0-9]/[a-zA-Z0-9_\-/]+)[\'"]',
            r'[\'"](https?://[a-zA-Z0-9\./\-_]+)[\'"]',
        ]
        for pat in patterns:
            for match in re.finditer(pat, content):
                found = match.group(1)
                full = urljoin(base_url, found) if found.startswith("/") else found
                if self.guard.is_safe(full) and full not in sitemap.endpoints:
                    sitemap.endpoints.append(full)
                    sitemap.detailed_endpoints.append(Endpoint(url=full, src="js"))

    async def _api_discovery(self, target: str, sitemap: SiteMap, session: Session) -> None:
        """Check for common API specifications."""
        common_specs = [
            "/openapi.json", "/swagger.json", "/api-docs", "/v1/api-docs",
            "/.well-known/api", "/graphql", "/graphiql", "/schema.json",
        ]
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for spec in common_specs:
                url = urljoin(base, spec)
                try:
                    async with self.bucket:
                        resp = await client.get(url)
                    if resp.status_code == 200:
                        sitemap.api_schemas.append(url)
                        if url not in sitemap.endpoints:
                            sitemap.endpoints.append(url)
                except Exception:
                    pass

    def _is_binary(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self._ignored_ext)
