"""
Advanced JavaScript Analyzer — TIER 2.
Deep analysis of client-side code for secrets, sensitive APIs, and business logic.
Replaces ZAP's JS-related scripts and passive rules.
Target: React/Vue/Angular/Svelte SPAs.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx
from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster
from medusa.engine.modules.web.crawler import SiteMap

__all__ = ["JSAnalyzer"]

logger = logging.getLogger(__name__)

# ── Secret & Sensitive Patterns ──────────────────────────────────────────────

# (pattern, name, severity, description, category)
JS_PATTERNS: list[tuple[str, str, str, str, str]] = [
    (r"(?i)api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "API Key", "high", "Hardcoded API key found in JavaScript source.", "A02:2021-Cryptographic Failures"),
    (r"(?i)aws[_-]?secret[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", "AWS Secret Key", "critical", "Hardcoded AWS secret key found — immediate credential compromise.", "A02:2021-Cryptographic Failures"),
    (r"(?i)firebase[_-]?database[_-]?url\s*[:=]\s*['\"](https?://[a-zA-Z0-9\-\.]+firebaseio\.com)['\"]", "Firebase DB URL", "medium", "Firebase database URL exposed — test for public access.", "A05:2021-Security Misconfiguration"),
    (r"(?i)jwt[_-]?secret\s*[:=]\s*['\"]([^'\"]{10,})['\"]", "JWT Signing Secret", "critical", "Hardcoded JWT secret found — session forgery possible.", "A02:2021-Cryptographic Failures"),
    (r"eval\s*\(\s*[^)]+\)", "Dynamic Evaluation (eval)", "medium", "Use of 'eval()' detected — potential XSS or injection vector.", "A03:2021-Injection"),
    (r"\.innerHTML\s*=", "Unsafe DOM Sinks (innerHTML)", "low", "Direct use of innerHTML detected — risk of DOM-based XSS.", "A03:2021-Injection"),
    (r"document\.domain\s*=", "Document Domain Modification", "low", "Modifying document.domain can weaken Same-Origin Policy.", "A05:2021-Security Misconfiguration"),
    (r"(?i)password\s*[:=]\s*['\"]([^'\"]{4,})['\"]", "Hardcoded Password", "high", "Found string that looks like a hardcoded password.", "A07:2021-Identification and Authentication Failures"),
    (r"(?i)Bearer\s+[A-Za-z0-9._\-]{20,}", "Hardcoded Bearer Token", "high", "Static Bearer token found in client-side code.", "A07:2021-Identification and Authentication Failures"),
    (r"localStorage\.setItem\(", "Local Storage Access", "info", "App uses local storage — verify if sensitive data (tokens) is stored there.", "A02:2021-Cryptographic Failures"),
    (r"console\.(debug|log|dir)\(", "Verbose Logging", "info", "Production code uses verbose logging — may leak sensitive info.", "A05:2021-Security Misconfiguration"),
    (r"\bpostMessage\s*\(\s*[^,]+,\s*['\"]\*", "Insecure postMessage Wildcard", "high", "postMessage targetOrigin is '*' — risk of cross-origin data theft.", "A01:2021-Broken Access Control"),
]


class JSAnalyzer:
    """
    Analyzes JavaScript files for secrets, endpoints, and security weaknesses.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        broadcaster: WSBroadcaster | None = None,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.broadcaster = broadcaster or WSBroadcaster()

    async def run(self, sitemap: SiteMap, session: Session) -> None:
        """Analyze all discovered JS files in the sitemap."""
        if not sitemap.js_files:
            return

        total = len(sitemap.js_files)
        await self.broadcaster.log(session.id, "INFO", f"[js_analyzer] Analyzing {total} JavaScript files", "js_analyzer")

        async with httpx.AsyncClient(
            verify=False, timeout=15.0,
            headers={"User-Agent": "Medusa-Scanner/1.0"},
            follow_redirects=True,
        ) as client:
            tasks = []
            for i, js_url in enumerate(sitemap.js_files[:50]):  # Limit to 50 files for speed
                self.guard.check(js_url, "web.js_analyzer")
                tasks.append(self._analyze_file(client, js_url, session, i, total))

            await asyncio.gather(*tasks, return_exceptions=True)

        await self.broadcaster.emit_progress(session.id, "js_analyzer", 100, "done")

    async def _analyze_file(
        self,
        client: httpx.AsyncClient,
        url: str,
        session: Session,
        index: int,
        total: int,
    ) -> None:
        """Fetch and analyze a single JS file."""
        try:
            async with self.bucket:
                resp = await client.get(url)

            if resp.status_code != 200:
                return

            text = resp.text or ""
            findings_count = 0

            for pattern, name, severity, desc, owasp in JS_PATTERNS:
                for match in re.finditer(pattern, text):
                    snippet = match.group(0)
                    if len(snippet) > 200:
                        snippet = snippet[:197] + "..."

                    session.add_finding(
                        module="web.js_analyzer",
                        target=url,
                        title=f"{name} Found in JavaScript",
                        description=f"{desc}\n\nSnippet: `{snippet}`",
                        severity=severity,  # type: ignore
                        payload=snippet,
                        tags=["js", "client-side", "secrets" if "Key" in name else "weakness"],
                        owasp_category=owasp,
                        request=f"GET {url}",
                        response=text[match.start():match.end() + 200],
                    )
                    findings_count += 1
                    break  # Found one instance, move to next pattern for this file

            # Progress update every 5 files
            if index % 5 == 0:
                pct = int((index / max(total, 1)) * 100)
                await self.broadcaster.emit_progress(session.id, "js_analyzer", pct, "running")

        except Exception as exc:
            logger.debug("JS analysis error for %s: %s", url, exc)
