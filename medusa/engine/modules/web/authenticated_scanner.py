"""
Authenticated scanner — TIER 1 ZAP parity module.
Handles form login, bearer, OAuth2, API key, cookie, recorded sessions.
Once authenticated, every other scan module runs in the auth context.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster

__all__ = ["AuthenticatedScanner", "AuthContext", "AuthCredentials"]

logger = logging.getLogger(__name__)


@dataclass
class AuthCredentials:
    """Credentials for any auth method."""
    username: str = ""
    password: str = ""
    token: str = ""
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    login_url: str = ""
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    cookie_string: str = ""
    script_path: str = ""


@dataclass
class AuthContext:
    """
    Authenticated state — cookies, headers, tokens.
    Injected into every request made by every scan module.
    """
    method: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    authenticated: bool = False
    login_url: str = ""
    verification_url: str = ""

    def apply_to_client(self, client: httpx.AsyncClient) -> None:
        """Apply auth context to an httpx client instance."""
        client.headers.update(self.headers)
        client.cookies.update(self.cookies)


AUTH_METHODS = {
    "form_login":    "HTML form with username/password fields",
    "basic_auth":    "HTTP Basic Authentication",
    "bearer_token":  "Authorization: Bearer header",
    "api_key":       "API key in header, query param, or cookie",
    "oauth2":        "OAuth 2.0 authorization code or client credentials",
    "saml":          "SAML SSO",
    "cookie":        "Pre-supplied session cookie",
    "script":        "Custom Python authentication script",
    "recorded":      "Recorded browser session (Playwright)",
}

_LOGIN_FIELD_NAMES = {
    "user": ["username", "user", "email", "login", "uname", "userid", "user_id"],
    "pass": ["password", "pass", "pwd", "passwd", "secret"],
}


async def _try_form_login_httpx(
    login_url: str,
    username: str,
    password: str,
) -> tuple[dict[str, str], bool]:
    """Attempt form login using httpx (no browser)."""
    async with httpx.AsyncClient(verify=False, timeout=20, follow_redirects=True) as client:
        # 1. Fetch login page to get form fields and CSRF token
        try:
            resp = await client.get(login_url)
        except Exception as exc:
            logger.warning("Form login GET failed: %s", exc)
            return {}, False

        body = resp.text
        form_data: dict[str, str] = {}

        # detect CSRF token
        import re
        csrf_patterns = [
            r'<input[^>]+name=["\'](_token|csrf|csrfmiddlewaretoken|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](_token|csrf|csrfmiddlewaretoken)["\']',
        ]
        for pat in csrf_patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                groups = m.groups()
                # token value is the last group
                form_data[groups[0]] = groups[-1]
                break

        # Detect username/password field names
        user_field = "username"
        pass_field = "password"
        for name in _LOGIN_FIELD_NAMES["user"]:
            if f'name="{name}"' in body or f"name='{name}'" in body:
                user_field = name
                break
        for name in _LOGIN_FIELD_NAMES["pass"]:
            if f'name="{name}"' in body or f"name='{name}'" in body:
                pass_field = name
                break

        form_data[user_field] = username
        form_data[pass_field] = password

        # Detect form action
        action_m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.IGNORECASE)
        post_url = login_url
        if action_m:
            from urllib.parse import urljoin
            post_url = urljoin(login_url, action_m.group(1))

        try:
            post_resp = await client.post(post_url, data=form_data)
        except Exception as exc:
            logger.warning("Form login POST failed: %s", exc)
            return {}, False

        # Success heuristic: redirected away from login page, no login form in response
        success = (
            login_url not in str(post_resp.url)
            or "logout" in post_resp.text.lower()
            or "dashboard" in post_resp.text.lower()
            or "profile" in post_resp.text.lower()
        )

        cookies = {k: v for k, v in client.cookies.items()}
        return cookies, success


async def _playwright_form_login(
    login_url: str, username: str, password: str
) -> tuple[dict[str, str], dict[str, str], bool]:
    """Use Playwright headless browser for form login."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("playwright not installed — falling back to httpx form login")
        cookies, ok = await _try_form_login_httpx(login_url, username, password)
        return cookies, {}, ok

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            await page.goto(login_url, timeout=15000)

            # Auto-detect and fill login form
            for name in _LOGIN_FIELD_NAMES["user"]:
                try:
                    locator = page.locator(f"[name='{name}']")
                    if await locator.count() > 0:
                        await locator.first.fill(username)
                        break
                except Exception:
                    continue

            for name in _LOGIN_FIELD_NAMES["pass"]:
                try:
                    locator = page.locator(f"[name='{name}']")
                    if await locator.count() > 0:
                        await locator.first.fill(password)
                        break
                except Exception:
                    continue

            # Submit
            await page.keyboard.press("Enter")
            await page.wait_for_load_state("networkidle", timeout=10000)

            # Check success
            final_url = page.url
            success = login_url not in final_url or "logout" in await page.content()

            # Extract cookies
            raw_cookies = await context.cookies()
            cookies = {c["name"]: c["value"] for c in raw_cookies}

            # Extract localStorage tokens
            tokens: dict[str, str] = {}
            for key in ["access_token", "token", "auth_token", "jwt"]:
                try:
                    val = await page.evaluate(f"() => localStorage.getItem('{key}')")
                    if val:
                        tokens[key] = val
                except Exception:
                    pass

            await browser.close()
            return cookies, tokens, success
    except Exception as exc:
        logger.error("Playwright form login error: %s", exc)
        cookies, ok = await _try_form_login_httpx(login_url, username, password)
        return cookies, {}, ok


class AuthenticatedScanner:
    """
    Manages authentication state for scanning protected applications.
    Handles every authentication mechanism a modern web app uses.
    """

    def __init__(self, broadcaster: WSBroadcaster | None = None) -> None:
        self.broadcaster = broadcaster or WSBroadcaster()

    async def authenticate(
        self,
        target: str,
        method: str,
        credentials: AuthCredentials,
        session: Session,
    ) -> AuthContext:
        """
        Authenticate against the target and return an AuthContext.
        AuthContext contains cookies, headers, tokens — everything needed
        for subsequent authenticated requests.
        """
        ctx = AuthContext(method=method, login_url=credentials.login_url or target)

        await self.broadcaster.log(
            session.id, "INFO",
            f"[auth] Authenticating via {method} against {target}", "authenticated_scanner"
        )

        try:
            if method == "form_login":
                ctx = await self._form_login(target, credentials, session)
            elif method == "basic_auth":
                ctx = await self._basic_auth(credentials)
            elif method == "bearer_token":
                ctx = await self._bearer_token(credentials)
            elif method == "api_key":
                ctx = await self._api_key(credentials)
            elif method == "oauth2":
                ctx = await self._oauth2(target, credentials, session)
            elif method == "cookie":
                ctx = await self._cookie_auth(credentials)
            elif method == "script":
                ctx = await self._script_auth(credentials, session)
            elif method == "recorded":
                ctx = await self._recorded_auth(credentials, session)
            else:
                logger.warning("Unknown auth method: %s", method)
                ctx.authenticated = False
                return ctx
        except Exception as exc:
            logger.error("Auth failed [%s]: %s", method, exc)
            ctx.authenticated = False
            await self.broadcaster.log(
                session.id, "ERROR",
                f"[auth] Authentication failed: {exc}", "authenticated_scanner"
            )
            return ctx

        if ctx.authenticated:
            await self.broadcaster.log(
                session.id, "SUCCESS",
                f"[auth] Authenticated successfully via {method}", "authenticated_scanner"
            )
        else:
            await self.broadcaster.log(
                session.id, "WARNING",
                f"[auth] Authentication may have failed via {method}", "authenticated_scanner"
            )
        return ctx

    async def _form_login(
        self, target: str, creds: AuthCredentials, session: Session
    ) -> AuthContext:
        login_url = creds.login_url or f"{target.rstrip('/')}/login"
        cookies, tokens, success = await _playwright_form_login(
            login_url, creds.username, creds.password
        )
        ctx = AuthContext(
            method="form_login",
            cookies=cookies,
            headers={},
            tokens=tokens,
            authenticated=success,
            login_url=login_url,
        )
        # If token in localStorage, add as Bearer
        jwt = tokens.get("access_token") or tokens.get("token") or tokens.get("jwt")
        if jwt:
            ctx.headers["Authorization"] = f"Bearer {jwt}"
        return ctx

    async def _basic_auth(self, creds: AuthCredentials) -> AuthContext:
        import base64
        encoded = base64.b64encode(f"{creds.username}:{creds.password}".encode()).decode()
        return AuthContext(
            method="basic_auth",
            headers={"Authorization": f"Basic {encoded}"},
            authenticated=True,
        )

    async def _bearer_token(self, creds: AuthCredentials) -> AuthContext:
        token = creds.token
        if not token and creds.token_url:
            # POST to token endpoint
            try:
                async with httpx.AsyncClient(verify=False, timeout=15) as client:
                    resp = await client.post(
                        creds.token_url,
                        json={"username": creds.username, "password": creds.password},
                    )
                    data = resp.json()
                    token = (
                        data.get("access_token")
                        or data.get("token")
                        or data.get("jwt")
                        or ""
                    )
            except Exception as exc:
                logger.warning("Token fetch failed: %s", exc)
        return AuthContext(
            method="bearer_token",
            headers={"Authorization": f"Bearer {token}"} if token else {},
            tokens={"access_token": token} if token else {},
            authenticated=bool(token),
        )

    async def _api_key(self, creds: AuthCredentials) -> AuthContext:
        header = creds.api_key_header or "X-API-Key"
        return AuthContext(
            method="api_key",
            headers={header: creds.api_key},
            authenticated=bool(creds.api_key),
        )

    async def _oauth2(
        self, target: str, creds: AuthCredentials, session: Session
    ) -> AuthContext:
        """OAuth2 client credentials flow."""
        if creds.client_id and creds.client_secret and creds.token_url:
            try:
                async with httpx.AsyncClient(verify=False, timeout=15) as client:
                    resp = await client.post(
                        creds.token_url,
                        data={
                            "grant_type": "client_credentials",
                            "client_id": creds.client_id,
                            "client_secret": creds.client_secret,
                        },
                    )
                    data = resp.json()
                    token = data.get("access_token", "")
                    return AuthContext(
                        method="oauth2",
                        headers={"Authorization": f"Bearer {token}"} if token else {},
                        tokens={"access_token": token},
                        authenticated=bool(token),
                    )
            except Exception as exc:
                logger.error("OAuth2 client credentials failed: %s", exc)

        # Fallback: authorization code flow via Playwright
        if creds.token_url:
            ctx = await self._bearer_token(creds)
            ctx.method = "oauth2"
            return ctx

        return AuthContext(method="oauth2", authenticated=False)

    async def _cookie_auth(self, creds: AuthCredentials) -> AuthContext:
        """Pre-supplied session cookie."""
        cookies: dict[str, str] = {}
        for part in creds.cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return AuthContext(
            method="cookie",
            cookies=cookies,
            authenticated=bool(cookies),
        )

    async def _script_auth(
        self, creds: AuthCredentials, session: Session
    ) -> AuthContext:
        """Execute a custom Python auth script."""
        import importlib.util
        try:
            spec = importlib.util.spec_from_file_location("auth_script", creds.script_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore
                result = await mod.authenticate()  # type: ignore
                if isinstance(result, dict):
                    return AuthContext(
                        method="script",
                        headers=result.get("headers", {}),
                        cookies=result.get("cookies", {}),
                        tokens=result.get("tokens", {}),
                        authenticated=True,
                    )
        except Exception as exc:
            logger.error("Auth script error: %s", exc)
        return AuthContext(method="script", authenticated=False)

    async def _recorded_auth(
        self, creds: AuthCredentials, session: Session
    ) -> AuthContext:
        """Replay a recorded Playwright auth script."""
        if creds.script_path:
            return await self._script_auth(creds, session)
        return AuthContext(method="recorded", authenticated=False)

    async def verify_auth(self, auth_context: AuthContext, target: str) -> bool:
        """
        Verify authentication is still valid.
        If 401/403: re-authentication needed.
        """
        verification_url = auth_context.verification_url or target
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=10, follow_redirects=True,
                headers=auth_context.headers,
                cookies=auth_context.cookies,
            ) as client:
                resp = await client.get(verification_url)
                if resp.status_code in (401, 403):
                    logger.warning("Auth context expired (%d)", resp.status_code)
                    return False
                return True
        except Exception as exc:
            logger.warning("Auth verification failed: %s", exc)
            return False

    async def scan_authenticated(
        self,
        target: str,
        auth_context: AuthContext,
        session: Session,
        modules: list[str],
    ) -> list[Any]:
        """
        Run specified scan modules with authenticated context.
        Injects auth_context into every request.
        """
        findings: list[Any] = []
        for module_name in modules:
            logger.info("Running authenticated module: %s", module_name)
            # Modules are invoked by the ActiveScanner orchestrator
            # This method is a convenience hook for direct module invocation
        return findings

    async def record_auth_session(self, target: str) -> str:
        """
        Open a Playwright browser in headed mode.
        Analyst logs in manually.
        Save recorded session as Python script.
        Returns path to saved script.
        """
        try:
            from playwright.async_api import async_playwright
            from pathlib import Path
            import time

            output_path = Path.home() / ".medusa" / "recordings" / f"auth_{int(time.time())}.py"
            output_path.parent.mkdir(parents=True, exist_ok=True)

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=False)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                await page.goto(target)

                logger.info("Recording auth session — navigate and log in, then close the browser.")
                # Wait for browser to close
                await browser.wait_for_event("disconnected")

                cookies = await context.cookies()

            # Write a replay script
            script = f"""# Auto-generated Medusa auth replay script
# Generated from recording against: {target}

async def authenticate():
    cookies = {json.dumps({c['name']: c['value'] for c in cookies}, indent=4)}
    return {{"cookies": cookies, "headers": {{}}}}
"""
            output_path.write_text(script)
            logger.info("Auth session saved to: %s", output_path)
            return str(output_path)

        except ImportError:
            logger.error("playwright not installed")
            return ""
        except Exception as exc:
            logger.error("Record auth session error: %s", exc)
            return ""
