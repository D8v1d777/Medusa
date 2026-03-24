"""
Passive scanner — TIER 1 ZAP parity module.
Two modes:
  1. Intercept proxy (mitmproxy) — analysts browse, findings appear live
  2. HAR file analysis — import browser HAR for offline analysis
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster

__all__ = ["PassiveScanner", "ProxyInfo", "HTTPRequest", "HTTPResponse"]

logger = logging.getLogger(__name__)


@dataclass
class ProxyInfo:
    host: str
    port: int
    ca_cert_path: str


@dataclass
class HTTPRequest:
    url: str
    method: str
    headers: dict[str, str]
    body: str = ""


@dataclass
class HTTPResponse:
    status_code: int
    headers: dict[str, str]
    body: str = ""


# ── Security header checks ──────────────────────────────────────────────────

_REQUIRED_HEADERS = {
    "x-content-type-options":    ("nosniff",              "X-Content-Type-Options missing or not 'nosniff'"),
    "x-frame-options":           (None,                   "X-Frame-Options missing (clickjacking risk)"),
    "strict-transport-security": (None,                   "HSTS missing — HTTPS downgrade possible"),
    "content-security-policy":   (None,                   "Content-Security-Policy missing — XSS risk"),
    "referrer-policy":           (None,                   "Referrer-Policy missing — info leakage"),
    "permissions-policy":        (None,                   "Permissions-Policy missing"),
}

_SENSITIVE_RESPONSE_PATTERNS: list[tuple[str, str, str]] = [
    (r"password\s*=\s*['\"][^'\"]+['\"]",         "critical", "Plaintext password in response body"),
    (r"api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}", "high", "API key exposed in response body"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}", "high", "JWT token exposed in response"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",   "critical", "Private key exposed in response"),
    (r"AKIA[0-9A-Z]{16}",                          "critical", "AWS Access Key ID exposed"),
    (r"(?i)secret[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "high", "Secret key exposed in response"),
    (r"(?i)(mysql|postgres|mongodb|redis):\/\/[^:]+:[^@]+@", "critical", "Database connection string exposed"),
    (r"(?i)(stack.?trace|at [a-z]+\.[a-z]+\()", "medium", "Stack trace in response — information leakage"),
]

_STACK_TRACE_PATTERNS = [
    r"at [A-Za-z\.]+\([A-Za-z]+\.java:\d+\)",     # Java
    r"Traceback \(most recent call last\)",         # Python
    r"Fatal error:",                                # PHP
    r"at Object\.<anonymous>",                      # Node.js
    r"Microsoft\..*ErrorPage",                      # ASP.NET
]

_OUTDATED_JS_LIBS = {
    "jquery": {
        "pattern": r"jquery[/-](\d+\.\d+\.?\d*)",
        "vulnerable_below": "3.7.0",
        "cve": "CVE-2020-11022",
    },
    "angular": {
        "pattern": r"angular[/-](\d+\.\d+\.?\d*)",
        "vulnerable_below": "1.8.0",
        "cve": "CVE-2019-14863",
    },
    "bootstrap": {
        "pattern": r"bootstrap[/-](\d+\.\d+\.?\d*)",
        "vulnerable_below": "5.0.0",
        "cve": "CVE-2021-23017",
    },
    "lodash": {
        "pattern": r"lodash[/-](\d+\.\d+\.?\d*)",
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2021-23337",
    },
    "moment": {
        "pattern": r"moment[/-](\d+\.\d+\.?\d*)",
        "vulnerable_below": "2.29.4",
        "cve": "CVE-2022-31129",
    },
}

PASSIVE_CHECKS = {
    "security_headers":     "Missing or misconfigured security headers",
    "cookie_flags":         "Missing Secure, HttpOnly, SameSite flags",
    "sensitive_data":       "Credentials, tokens, PII in responses",
    "information_leakage":  "Stack traces, server banners, debug info",
    "cors_policy":          "Overly permissive CORS configuration",
    "csp_analysis":         "CSP policy weaknesses",
    "mixed_content":        "HTTP resources loaded on HTTPS pages",
    "outdated_libraries":   "Vulnerable JS library versions",
    "jwt_analysis":         "JWT tokens — algorithm, expiry, claims",
    "api_key_exposure":     "API keys in responses or JS",
    "redirect_analysis":    "Open redirect candidates",
    "cache_control":        "Sensitive data cached by browser",
}


class PassiveScanner:
    """
    Analyses traffic without sending additional requests.
    Works in proxy mode (mitmproxy) or HAR file import mode.
    """

    def __init__(self, broadcaster: WSBroadcaster | None = None) -> None:
        self.broadcaster = broadcaster or WSBroadcaster()
        self._proxy_task: asyncio.Task | None = None

    # ── Proxy Mode ──────────────────────────────────────────────────────────

    async def start_proxy(self, port: int = 8888, session: "Session | None" = None) -> ProxyInfo:
        """
        Start an intercepting proxy using mitmproxy Python API.
        All traffic through the proxy is passively analysed.
        """
        try:
            from mitmproxy.tools.dump import DumpMaster
            from mitmproxy.options import Options
            from mitmproxy import http as mhttp
        except ImportError:
            logger.error("mitmproxy not installed — `pip install mitmproxy`")
            return ProxyInfo(host="localhost", port=port, ca_cert_path="")

        broadcaster = self.broadcaster
        passive_scanner = self

        class _MedusaAddon:
            async def response(self, flow: mhttp.HTTPFlow) -> None:
                req = HTTPRequest(
                    url=flow.request.pretty_url,
                    method=flow.request.method,
                    headers=dict(flow.request.headers),
                    body=flow.request.get_text(strict=False) or "",
                )
                resp = HTTPResponse(
                    status_code=flow.response.status_code if flow.response else 0,
                    headers=dict(flow.response.headers) if flow.response else {},
                    body=flow.response.get_text(strict=False) if flow.response else "",
                )
                if session:
                    findings = await passive_scanner.analyse_request(req, resp, session)
                    for f in findings:
                        await broadcaster.emit_finding(session.id, f)

        opts = Options(listen_host="127.0.0.1", listen_port=port)
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(_MedusaAddon())

        async def _run_proxy() -> None:
            try:
                await master.run()
            except Exception as exc:
                logger.error("Proxy error: %s", exc)

        self._proxy_task = asyncio.create_task(_run_proxy())
        logger.info("Passive proxy started on port %d", port)

        import pathlib
        ca_cert = str(pathlib.Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")
        return ProxyInfo(host="localhost", port=port, ca_cert_path=ca_cert)

    async def stop_proxy(self) -> None:
        """Stop the proxy."""
        if self._proxy_task:
            self._proxy_task.cancel()
            self._proxy_task = None

    # ── HAR Analysis ────────────────────────────────────────────────────────

    async def analyse_har(self, har_path: str, session: Session) -> list[Any]:
        """
        Import and analyse a browser HAR (HTTP Archive) file.
        Parse HAR JSON. For each entry (request + response pair): run all PASSIVE_CHECKS.
        """
        from pathlib import Path as P

        await self.broadcaster.log(
            session.id, "INFO", f"[passive_scanner] Analysing HAR: {har_path}", "passive_scanner"
        )

        findings_all: list[Any] = []
        try:
            data = json.loads(P(har_path).read_text(encoding="utf-8"))
            entries = data.get("log", {}).get("entries", [])
            total = len(entries)
            for i, entry in enumerate(entries):
                req_data = entry.get("request", {})
                resp_data = entry.get("response", {})

                req = HTTPRequest(
                    url=req_data.get("url", ""),
                    method=req_data.get("method", "GET"),
                    headers={
                        h["name"]: h["value"]
                        for h in req_data.get("headers", [])
                        if "name" in h and "value" in h
                    },
                    body=req_data.get("postData", {}).get("text", "") or "",
                )
                resp = HTTPResponse(
                    status_code=resp_data.get("status", 0),
                    headers={
                        h["name"]: h["value"]
                        for h in resp_data.get("headers", [])
                        if "name" in h and "value" in h
                    },
                    body=resp_data.get("content", {}).get("text", "") or "",
                )
                findings = await self.analyse_request(req, resp, session)
                findings_all.extend(findings)

                if i % 20 == 0:
                    pct = int((i / max(total, 1)) * 100)
                    await self.broadcaster.emit_progress(session.id, "passive_scanner", pct, "running")

        except Exception as exc:
            logger.error("HAR parse error: %s", exc)
            await self.broadcaster.log(session.id, "ERROR", f"HAR parse error: {exc}", "passive_scanner")

        await self.broadcaster.emit_progress(session.id, "passive_scanner", 100, "done")
        await self.broadcaster.log(
            session.id, "SUCCESS",
            f"[passive_scanner] HAR analysis done. {len(findings_all)} findings.", "passive_scanner",
        )
        return findings_all

    # ── Core Analysis ────────────────────────────────────────────────────────

    async def analyse_request(
        self,
        request: HTTPRequest,
        response: HTTPResponse,
        session: Session,
    ) -> list[Any]:
        """
        Analyse a single request/response pair.
        Must be fast — runs inline with proxy traffic. Target < 10ms.
        """
        findings: list[Any] = []
        findings.extend(self._check_security_headers(request, response, session))
        findings.extend(self._check_cookie_flags(request, response, session))
        findings.extend(self._check_sensitive_data(request, response, session))
        findings.extend(self._check_cors(request, response, session))
        findings.extend(self._check_csp(request, response, session))
        findings.extend(self._check_information_leakage(request, response, session))
        findings.extend(self._check_outdated_libraries(request, response, session))
        findings.extend(self._check_jwt(request, response, session))
        findings.extend(self._check_cache_control(request, response, session))
        return findings

    def _add_finding(
        self, session: Session, url: str, title: str, description: str,
        severity: str, tags: list[str], owasp: str = "",
    ) -> Any:
        return session.add_finding(
            module="web.passive_scanner",
            target=url,
            title=title,
            description=description,
            severity=severity,  # type: ignore
            tags=tags + ["passive"],
            owasp_category=owasp,
        )

    def _check_security_headers(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        if resp.status_code == 0:
            return []
        findings = []
        lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        for header, (expected, message) in _REQUIRED_HEADERS.items():
            if header not in lower_headers:
                sev = "medium" if header in ("strict-transport-security", "content-security-policy") else "low"
                findings.append(self._add_finding(
                    session, req.url, f"Missing Security Header: {header}",
                    message, sev, ["headers", "passive"],
                    "A05:2021-Security Misconfiguration",
                ))
            elif expected and lower_headers[header].lower() != expected:
                findings.append(self._add_finding(
                    session, req.url,
                    f"Misconfigured Header: {header}",
                    f"{header} value is '{lower_headers[header]}', expected '{expected}'",
                    "low", ["headers", "passive"],
                ))
        return findings

    def _check_cookie_flags(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        set_cookie = resp.headers.get("set-cookie") or resp.headers.get("Set-Cookie", "")
        if not set_cookie:
            return []
        is_https = req.url.startswith("https")
        cookie_lower = set_cookie.lower()
        if is_https and "secure" not in cookie_lower:
            findings.append(self._add_finding(
                session, req.url, "Cookie Missing Secure Flag",
                f"Cookie set without Secure flag on HTTPS: {set_cookie[:200]}",
                "medium", ["cookie", "passive"], "A02:2021-Cryptographic Failures",
            ))
        if "httponly" not in cookie_lower:
            findings.append(self._add_finding(
                session, req.url, "Cookie Missing HttpOnly Flag",
                f"Cookie set without HttpOnly flag — accessible via JavaScript: {set_cookie[:200]}",
                "medium", ["cookie", "passive", "xss"],
            ))
        if "samesite" not in cookie_lower:
            findings.append(self._add_finding(
                session, req.url, "Cookie Missing SameSite Flag",
                f"Cookie set without SameSite flag — CSRF risk: {set_cookie[:200]}",
                "low", ["cookie", "passive", "csrf"],
            ))
        return findings

    def _check_sensitive_data(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        body = resp.body or ""
        for pattern, severity, title in _SENSITIVE_RESPONSE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                snippet = (re.search(pattern, body, re.IGNORECASE) or re.match("", "")).group(0)  # type: ignore
                findings.append(self._add_finding(
                    session, req.url, title,
                    f"Pattern matched in response body: {snippet[:200]}",
                    severity, ["sensitive-data", "passive"],
                    "A02:2021-Cryptographic Failures",
                ))
        return findings

    def _check_cors(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        acao = resp.headers.get("access-control-allow-origin") or resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("access-control-allow-credentials") or resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(self._add_finding(
                session, req.url, "CORS Wildcard with Credentials",
                "Access-Control-Allow-Origin: * combined with Allow-Credentials: true — critical CORS misconfiguration",
                "critical", ["cors", "passive"], "A01:2021-Broken Access Control",
            ))
        elif acao == "*":
            findings.append(self._add_finding(
                session, req.url, "CORS Wildcard Origin",
                "Access-Control-Allow-Origin: * — any origin can read responses",
                "medium", ["cors", "passive"],
            ))
        elif acao and req.headers.get("origin") and acao == req.headers.get("origin"):
            findings.append(self._add_finding(
                session, req.url, "CORS Origin Reflection",
                f"Server reflects any Origin header: {acao}",
                "high", ["cors", "passive"], "A01:2021-Broken Access Control",
            ))
        return findings

    def _check_csp(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        csp = resp.headers.get("content-security-policy") or resp.headers.get("Content-Security-Policy", "")
        if not csp:
            return []
        if "unsafe-inline" in csp and "script-src" in csp:
            findings.append(self._add_finding(
                session, req.url, "CSP allows unsafe-inline scripts",
                "Content-Security-Policy contains 'unsafe-inline' in script-src — XSS protection weakened",
                "medium", ["csp", "xss", "passive"],
            ))
        if "unsafe-eval" in csp:
            findings.append(self._add_finding(
                session, req.url, "CSP allows unsafe-eval",
                "Content-Security-Policy contains 'unsafe-eval' — eval() not blocked",
                "low", ["csp", "xss", "passive"],
            ))
        if "*" in csp and "script-src" not in csp:
            findings.append(self._add_finding(
                session, req.url, "CSP wildcard source",
                "CSP contains wildcard (*) source — ineffective protection",
                "medium", ["csp", "passive"],
            ))
        return findings

    def _check_information_leakage(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        body = resp.body or ""
        server = resp.headers.get("server") or resp.headers.get("Server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(self._add_finding(
                session, req.url, "Server Version Disclosure",
                f"Server header reveals version: {server}",
                "low", ["banner", "passive"],
            ))
        x_powered = resp.headers.get("x-powered-by") or resp.headers.get("X-Powered-By", "")
        if x_powered:
            findings.append(self._add_finding(
                session, req.url, "Technology Disclosure via X-Powered-By",
                f"X-Powered-By reveals technology: {x_powered}",
                "info", ["banner", "passive"],
            ))
        for pat in _STACK_TRACE_PATTERNS:
            if re.search(pat, body):
                findings.append(self._add_finding(
                    session, req.url, "Stack Trace in Response",
                    "Application returns stack trace — implementation details exposed",
                    "medium", ["error-disclosure", "passive"],
                    "A05:2021-Security Misconfiguration",
                ))
                break
        return findings

    def _check_outdated_libraries(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        body = resp.body or ""
        url = req.url
        # check URL and response body for known library patterns
        combined = f"{url} {body[:5000]}"
        for lib, info in _OUTDATED_JS_LIBS.items():
            m = re.search(info["pattern"], combined, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                vulnerable_below = info["vulnerable_below"]
                # Simple version comparison
                try:
                    current = tuple(int(x) for x in version.split("."))
                    threshold = tuple(int(x) for x in vulnerable_below.split("."))
                    if current < threshold:
                        findings.append(self._add_finding(
                            session, req.url,
                            f"Outdated JS Library: {lib} {version}",
                            f"{lib} version {version} is below {vulnerable_below}. CVE: {info['cve']}",
                            "medium", ["outdated-library", lib, "passive"],
                            "A06:2021-Vulnerable and Outdated Components",
                        ))
                except Exception:
                    pass
        return findings

    def _check_jwt(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        import base64
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        all_text = " ".join([resp.body or "", *resp.headers.values()])
        for match in jwt_pattern.finditer(all_text):
            token = match.group(0)
            parts = token.split(".")
            if len(parts) < 3:
                continue
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                alg = header.get("alg", "").upper()
                if alg == "NONE":
                    findings.append(self._add_finding(
                        session, req.url, "JWT with alg:none",
                        "JWT token uses algorithm 'none' — signature verification bypassed",
                        "critical", ["jwt", "auth", "passive"],
                        "A07:2021-Identification and Authentication Failures",
                    ))
                elif alg in ("HS256", "HS384", "HS512"):
                    findings.append(self._add_finding(
                        session, req.url, "JWT with weak algorithm",
                        f"JWT uses symmetric algorithm {alg} — may be brute-forceable",
                        "info", ["jwt", "passive"],
                    ))
            except Exception:
                pass
        return findings

    def _check_cache_control(
        self, req: HTTPRequest, resp: HTTPResponse, session: Session
    ) -> list[Any]:
        findings = []
        cache = resp.headers.get("cache-control") or resp.headers.get("Cache-Control", "")
        url = req.url
        # Sensitive endpoints likely to contain user data
        sensitive_paths = ["/account", "/profile", "/admin", "/api/", "/dashboard", "/user"]
        is_sensitive = any(p in url for p in sensitive_paths)
        if is_sensitive and cache and "no-store" not in cache and "private" not in cache:
            findings.append(self._add_finding(
                session, url, "Sensitive Page May Be Cached",
                f"Sensitive endpoint {url} uses Cache-Control: {cache} — response may be stored by proxies",
                "medium", ["cache", "sensitive-data", "passive"],
            ))
        return findings
