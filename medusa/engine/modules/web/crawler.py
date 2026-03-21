"""Web crawler — discovery and sitemap building."""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.session import Session

__all__ = ["Crawler", "SiteMap"]

logger = logging.getLogger(__name__)


def _attr_str(val: Any) -> str:
    """Coerce bs4 attribute value (str, list, or other) to a single string."""
    if val is None:
        return ""
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val)


@dataclass
class Endpoint:
    """Discovered endpoint."""

    path: str
    method: str
    params: list[str]
    auth_required: bool = False


@dataclass
class Form:
    """Discovered form."""

    action: str
    method: str
    inputs: list[dict[str, Any]]


@dataclass
class SiteMap:
    """Crawl result sitemap."""

    base_url: str
    endpoints: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    api_schemas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize for JSON."""
        return {
            "base_url": self.base_url,
            "endpoints": self.endpoints,
            "forms": [asdict(f) for f in self.forms],
            "js_files": self.js_files,
            "cookies": self.cookies,
            "technologies": self.technologies,
            "api_schemas": self.api_schemas,
        }


class Crawler:
    """Async HTTP crawler with scope enforcement."""

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        max_depth: int = 3,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.max_depth = max_depth
        self._visited: set[str] = set()
        self._ignored = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".zip"}

    def _should_ignore(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(e) for e in self._ignored)

    async def run(self, target: str, session: Session) -> SiteMap:
        """Crawl target and build sitemap."""
        self.guard.check(target, "web.crawler")
        self._visited.clear()
        sitemap = SiteMap(base_url=target)
        queue: list[tuple[str, int]] = [(target, 0)]

        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            while queue:
                url, depth = queue.pop(0)
                if depth > self.max_depth or url in self._visited:
                    continue
                self._visited.add(url)

                async with self.bucket:
                    try:
                        resp = await client.get(url)
                    except Exception as e:
                        logger.debug("Crawl failed %s: %s", url, e)
                        continue

                soup = BeautifulSoup(resp.text, "html.parser")

                for a in soup.find_all("a", href=True):
                    full = urljoin(url, _attr_str(a.get("href")))
                    if self.guard.is_safe(full) and not self._should_ignore(full):
                        clean = full.split("#")[0]
                        if clean not in sitemap.endpoints:
                            sitemap.endpoints.append(clean)
                        if clean not in self._visited and depth < self.max_depth:
                            queue.append((clean, depth + 1))

                for form in soup.find_all("form"):
                    action = _attr_str(form.get("action"))
                    method = _attr_str(form.get("method", "get")).lower()
                    inputs = []
                    for inp in form.find_all(["input", "textarea"]):
                        if inp.get("name"):
                            inputs.append(
                                {
                                    "name": inp.get("name"),
                                    "type": inp.get("type", "text"),
                                    "value": inp.get("value", ""),
                                }
                            )
                    sitemap.forms.append(
                        Form(
                            action=urljoin(url, action),
                            method=method,
                            inputs=inputs,
                        )
                    )

        return sitemap
