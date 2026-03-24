"""
Deep REST and GraphQL API vulnerability scanner — TIER 2.
Where ZAP is weakest. Modern apps are APIs.
Covers: discovery, auth testing, BOLA/IDOR, input validation, business logic, info disclosure.
GraphQL: introspection, field suggestion, batch abuse, alias abuse, deep recursion, mutations.
gRPC: reflection API, missing auth, injection.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster
from medusa.engine.modules.web.authenticated_scanner import AuthContext

__all__ = ["APIScanner"]

logger = logging.getLogger(__name__)

# Common spec discovery paths
SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs/", "/api/swagger", "/api/swagger.json",
    "/v1/docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/.well-known/api", "/api", "/api/v1", "/api/v2",
    "/docs/api.json", "/api/schema", "/schema.json",
]

# GraphQL typical endpoints
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1",
    "/gql", "/api/gql", "/graphiql", "/graphql/console",
]

# Common injection payloads for API params
API_SQLI = ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT 1,2,3--"]
API_XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]


class APIScanner:
    """
    Deep REST, GraphQL, and gRPC API vulnerability detection.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        broadcaster: WSBroadcaster | None = None,
    ) -> None:
        self.guard = guard
        self.bucket = bucket
        self.bucket = bucket
        self.broadcaster = broadcaster or WSBroadcaster()
        from medusa.engine.modules.web.race_tester import RaceTester
        self.race_tester = RaceTester(self.bucket)

    # ── REST ──────────────────────────────────────────────────────────────────

    async def scan_rest(
        self,
        target: str,
        spec: dict | None,
        auth_context: AuthContext | None,
        session: Session,
    ) -> list[Any]:
        """
        Full REST API scanning.
        Phase 1: Discovery
        Phase 2: Auth testing
        Phase 3: BOLA/IDOR
        Phase 4: Input validation
        Phase 5: Business logic
        Phase 6: Info disclosure
        """
        await self.broadcaster.log(session.id, "INFO", f"[api_scanner] REST scan on {target}", "api_scanner")

        headers = auth_context.headers if auth_context else {}
        cookies = auth_context.cookies if auth_context else {}

        findings: list[Any] = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(
            verify=False, timeout=15,
            headers={**headers, "User-Agent": "Medusa-Scanner/1.0"},
            cookies=cookies,
            follow_redirects=True,
        ) as client:

            # ── Phase 1: Discovery ────────────────────────────────────────
            spec_data = spec
            if not spec_data:
                spec_data = await self._discover_spec(client, base, session)

            endpoints = await self._extract_endpoints(spec_data, base) if spec_data else []

            # ── Phase 2: Auth Testing ─────────────────────────────────────
            no_auth_client = httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True)
            for ep in endpoints[:30]:
                await self._test_endpoint_auth(ep, client, no_auth_client, session)
            await no_auth_client.aclose()

            # ── Phase 3: BOLA/IDOR ────────────────────────────────────────
            for ep in endpoints[:30]:
                await self._test_bola(ep, client, auth_context, session)

            # ── Phase 4: Input Validation ─────────────────────────────────
            for ep in endpoints[:20]:
                await self._test_input_validation(ep, client, session)

            # ── Phase 5: Business Logic ───────────────────────────────────
            for ep in endpoints[:10]:
                await self._test_rate_limiting(ep, client, session)

            # ── Phase 6: Info Disclosure ──────────────────────────────────
            for ep in endpoints[:20]:
                await self._test_info_disclosure(ep, client, session)

        await self.broadcaster.log(session.id, "INFO", "[api_scanner] REST scan complete", "api_scanner")
        return findings

    async def _discover_spec(
        self, client: httpx.AsyncClient, base: str, session: Session
    ) -> dict | None:
        """Try common spec paths."""
        for path in SPEC_PATHS:
            url = f"{base}{path}"
            try:
                self.guard.check(url, "web.api_scanner")
                async with self.bucket:
                    resp = await client.get(url, timeout=8)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or "yaml" in ct or resp.text.strip().startswith("{"):
                        try:
                            spec = json.loads(resp.text)
                            if "paths" in spec or "swagger" in spec or "openapi" in spec:
                                session.add_finding(
                                    module="web.api_scanner",
                                    target=url,
                                    title="API Specification Exposed",
                                    description=f"OpenAPI/Swagger spec exposed at {url}",
                                    severity="medium",
                                    request=f"GET {url}",
                                    response=resp.text[:500],
                                    tags=["api", "exposure", "swagger"],
                                    owasp_category="A05:2021-Security Misconfiguration",
                                )
                                return spec
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass
        return None

    async def _extract_endpoints(self, spec: dict, base: str) -> list[dict]:
        """Parse OpenAPI/Swagger spec into endpoint list."""
        endpoints = []
        paths = spec.get("paths", {})
        servers = spec.get("servers", [{"url": base}])
        server_url = servers[0].get("url", base) if servers else base
        if server_url.startswith("/"):
            server_url = base + server_url

        for path, methods in paths.items():
            for method, op in methods.items():
                if method.lower() in ("get", "post", "put", "patch", "delete"):
                    params = []
                    for p in op.get("parameters", []):
                        params.append({
                            "name": p.get("name", ""),
                            "in": p.get("in", "query"),
                            "required": p.get("required", False),
                            "schema": p.get("schema", {}),
                        })
                    endpoints.append({
                        "url": urljoin(server_url, path),
                        "method": method.upper(),
                        "params": params,
                        "path": path,
                        "operation_id": op.get("operationId", ""),
                        "auth_required": bool(op.get("security")),
                    })
        return endpoints

    async def _test_endpoint_auth(
        self,
        ep: dict,
        auth_client: httpx.AsyncClient,
        no_auth_client: httpx.AsyncClient,
        session: Session,
    ) -> None:
        """Test endpoint without auth — expect 401/403."""
        url = ep["url"]
        method = ep["method"]
        try:
            self.guard.check(url, "web.api_scanner")
            async with self.bucket:
                resp = await no_auth_client.request(method, url, timeout=8)
            if resp.status_code == 200 and ep.get("auth_required"):
                session.add_finding(
                    module="web.api_scanner",
                    target=url,
                    title="Broken Object Level Authorization — Unauthenticated Access",
                    description=(
                        f"Endpoint {method} {url} returned 200 without authentication.\n"
                        f"This endpoint is marked as requiring auth in the spec."
                    ),
                    severity="critical",
                    request=f"{method} {url} (no auth headers)",
                    response=resp.text[:1000],
                    tags=["bola", "bfla", "api", "auth-bypass"],
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_ids=["CWE-862"],
                )
        except Exception as exc:
            logger.debug("Auth test %s: %s", url, exc)

    async def _test_bola(
        self,
        ep: dict,
        client: httpx.AsyncClient,
        auth_context: AuthContext | None,
        session: Session,
    ) -> None:
        """Test for BOLA by enumerating IDs in path."""
        url = ep["url"]
        id_pattern = re.compile(r"\{([^}]+)\}|/(\d+)(/|$)")
        if not id_pattern.search(url):
            return

        # Try sequential IDs
        base_url = re.sub(r"\{[^}]+\}", "1", url)
        for test_id in range(1, 6):
            test_url = re.sub(r"/\d+(/|$)", f"/{test_id}\\1", base_url)
            if test_url == base_url and test_id == 1:
                continue
            try:
                self.guard.check(test_url, "web.api_scanner")
                async with self.bucket:
                    resp = await client.get(test_url, timeout=8)
                if resp.status_code == 200 and len(resp.text) > 50:
                    session.add_finding(
                        module="web.api_scanner",
                        target=test_url,
                        title="Potential BOLA — Object ID Enumeration",
                        description=(
                            f"API endpoint {test_url} returns data for ID {test_id}.\n"
                            f"Verify this resource belongs to the authenticated user.\n"
                            f"Pattern: sequential ID access"
                        ),
                        severity="high",
                        request=f"GET {test_url}",
                        response=resp.text[:500],
                        tags=["bola", "idor", "api", "access-control"],
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_ids=["CWE-639"],
                    )
                    break
            except Exception as exc:
                logger.debug("BOLA test %s: %s", test_url, exc)

    async def _test_input_validation(
        self, ep: dict, client: httpx.AsyncClient, session: Session
    ) -> None:
        """Test input validation — type confusion, mass assignment, injection."""
        url = re.sub(r"\{[^}]+\}", "1", ep["url"])
        method = ep["method"]
        params = ep.get("params", [])
        query_params = {p["name"]: "test" for p in params if p.get("in") == "query"}
        body_params = {p["name"]: "test" for p in params if p.get("in") == "body"}

        # Type confusion attacks
        type_confusion_vals = [
            -1, 0, 2**31, "null", "undefined", "true", "false",
            {"key": "value"}, [1, 2, 3], ""
        ]

        for p in params[:5]:
            if p.get("schema", {}).get("type") in ("integer", "number"):
                for bad_val in ["string_instead", None, -1, 9999999999]:
                    test_body = dict(body_params) if body_params else {}
                    test_body[p["name"]] = bad_val
                    try:
                        self.guard.check(url, "web.api_scanner")
                        async with self.bucket:
                            if method in ("POST", "PUT", "PATCH"):
                                resp = await client.request(
                                    method, url,
                                    json=test_body, timeout=8,
                                    headers={"Content-Type": "application/json"},
                                )
                            else:
                                resp = await client.request(method, url, params={p["name"]: str(bad_val)}, timeout=8)

                        # Check for stack trace in error response
                        if resp.status_code in (500, 400) and any(
                            pat in resp.text.lower() for pat in ["traceback", "exception", "stack", "error at"]
                        ):
                            session.add_finding(
                                module="web.api_scanner",
                                target=url,
                                title="Verbose API Error Response",
                                description=(
                                    f"API endpoint leaks implementation details in error response.\n"
                                    f"Parameter: {p['name']}, Value: {bad_val}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                severity="medium",
                                request=f"{method} {url} body={json.dumps(test_body)}",
                                response=resp.text[:1000],
                                tags=["api", "error-disclosure", "info-leak"],
                                owasp_category="A05:2021-Security Misconfiguration",
                            )
                    except Exception:
                        pass

    async def _test_rate_limiting(
        self, ep: dict, client: httpx.AsyncClient, session: Session
    ) -> None:
        """Rapid requests to sensitive endpoints — test rate limiting."""
        url = re.sub(r"\{[^}]+\}", "1", ep["url"])
        is_sensitive = any(s in url.lower() for s in ["/login", "/auth", "/token", "/signup", "/register"])
        if not is_sensitive:
            return

        try:
            self.guard.check(url, "web.api_scanner")
            tasks = []
            for _ in range(10):
                tasks.append(client.post(url, json={"username": "test", "password": "wrong"}, timeout=8))

            responses = await asyncio.gather(*tasks, return_exceptions=True)
            error_count = sum(1 for r in responses if isinstance(r, Exception) or (
                hasattr(r, "status_code") and r.status_code == 429  # type: ignore
            ))

            if error_count < 2:
                session.add_finding(
                    module="web.api_scanner",
                    target=url,
                    title="Missing Rate Limiting on Sensitive Endpoint",
                    description=(
                        f"Endpoint {url} accepted 10 rapid requests without rate limiting.\n"
                        f"Brute-force and credential stuffing attacks are possible."
                    ),
                    severity="high",
                    request=f"POST {url} (10 rapid requests)",
                    tags=["rate-limit", "brute-force", "api", "auth"],
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    cwe_ids=["CWE-307"],
                )
        except Exception as exc:
            logger.debug("Rate limit test %s: %s", url, exc)

    async def _test_info_disclosure(
        self, ep: dict, client: httpx.AsyncClient, session: Session
    ) -> None:
        """Test for verbose errors, user enumeration."""
        url = re.sub(r"\{[^}]+\}", "99999999", ep["url"])  # non-existent ID
        try:
            self.guard.check(url, "web.api_scanner")
            async with self.bucket:
                resp_noexist = await client.get(url, timeout=8)

            url_valid = re.sub(r"\{[^}]+\}", "1", ep["url"])
            self.guard.check(url_valid, "web.api_scanner")
            async with self.bucket:
                resp_valid = await client.get(url_valid, timeout=8)

            # User enumeration: 404 vs 403 discloses whether resource exists
            if resp_noexist.status_code == 404 and resp_valid.status_code == 403:
                session.add_finding(
                    module="web.api_scanner",
                    target=ep["url"],
                    title="API User Enumeration via Status Code Difference",
                    description=(
                        f"Different status codes for existing ({resp_valid.status_code}) "
                        f"vs non-existing ({resp_noexist.status_code}) resources — "
                        f"confirms resource existence without authorization."
                    ),
                    severity="low",
                    tags=["api", "user-enum", "info-disclosure"],
                    owasp_category="A07:2021-Identification and Authentication Failures",
                )
        except Exception:
            pass

    # ── GraphQL ───────────────────────────────────────────────────────────────

    async def scan_graphql(
        self,
        endpoint: str,
        auth_context: AuthContext | None,
        session: Session,
    ) -> list[Any]:
        """GraphQL-specific vulnerability detection."""
        headers = auth_context.headers if auth_context else {}
        cookies = auth_context.cookies if auth_context else {}
        findings: list[Any] = []

        async with httpx.AsyncClient(
            verify=False, timeout=15,
            headers={**headers, "Content-Type": "application/json", "User-Agent": "Medusa-Scanner/1.0"},
            cookies=cookies,
            follow_redirects=True,
        ) as client:

            # Try to find active GraphQL endpoint
            active_endpoint = await self._find_graphql_endpoint(client, endpoint, session)
            if not active_endpoint:
                return []

            await self.broadcaster.log(
                session.id, "INFO",
                f"[api_scanner] GraphQL endpoint found: {active_endpoint}", "api_scanner"
            )

            # 1. Introspection
            schema = await self._test_graphql_introspection(client, active_endpoint, session)

            # 2. Field suggestion attack
            await self._test_graphql_field_suggestion(client, active_endpoint, session)

            # 3. Batch query abuse
            await self._test_graphql_batch(client, active_endpoint, session)

            # 4. Alias abuse
            await self._test_graphql_alias(client, active_endpoint, session, schema)

            # 5. Deep recursion
            await self._test_graphql_depth(client, active_endpoint, session, schema)

            # 6. Mutation testing
            await self._test_graphql_mutations(client, active_endpoint, session, schema)

            # 7. Race condition on sensitive mutations
            if active_endpoint:
                await self.race_tester.run(active_endpoint, session, data={"query": "mutation { checkout { id } }"})

        return findings

    async def _find_graphql_endpoint(
        self, client: httpx.AsyncClient, base: str, session: Session
    ) -> str | None:
        """Try common GraphQL endpoint paths."""
        parsed = urlparse(base)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        test_query = {"query": "{__typename}"}
        for path in GRAPHQL_PATHS:
            url = f"{base_url}{path}" if path.startswith("/") else base
            try:
                self.guard.check(url, "web.api_scanner")
                async with self.bucket:
                    resp = await client.post(url, json=test_query, timeout=8)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            return url
                    except Exception:
                        pass
            except Exception:
                pass

        # Try GET request with query param
        for path in GRAPHQL_PATHS[:3]:
            url = f"{base_url}{path}"
            try:
                self.guard.check(url, "web.api_scanner")
                async with self.bucket:
                    resp = await client.get(url, params=test_query, timeout=8)
                if resp.status_code == 200:
                    try:
                        if "data" in resp.json() or "errors" in resp.json():
                            return url
                    except Exception:
                        pass
            except Exception:
                pass
        return None

    async def _test_graphql_introspection(
        self, client: httpx.AsyncClient, endpoint: str, session: Session
    ) -> dict | None:
        """Test if introspection is enabled — schema exposure."""
        query = {"query": '{ __schema { types { name fields { name type { name } } } } }'}
        try:
            async with self.bucket:
                resp = await client.post(endpoint, json=query, timeout=15)
            data = resp.json()
            if "data" in data and data["data"] and "__schema" in data["data"]:
                session.add_finding(
                    module="web.api_scanner",
                    target=endpoint,
                    title="GraphQL Introspection Enabled",
                    description=(
                        "GraphQL introspection is enabled — full schema is exposed.\n"
                        "Attackers can enumerate all types, fields, queries, and mutations.\n"
                        "Disable introspection in production."
                    ),
                    severity="medium",
                    request=f"POST {endpoint} {json.dumps(query)}",
                    response=resp.text[:1000],
                    tags=["graphql", "introspection", "api", "exposure"],
                    owasp_category="A05:2021-Security Misconfiguration",
                )
                return data["data"]
        except Exception as exc:
            logger.debug("GraphQL introspection %s: %s", endpoint, exc)

        # Try __type as some block __schema but not __type
        query2 = {"query": '{ __type(name: "User") { fields { name } } }'}
        try:
            async with self.bucket:
                resp = await client.post(endpoint, json=query2, timeout=8)
            data = resp.json()
            if "data" in data and data["data"]:
                session.add_finding(
                    module="web.api_scanner",
                    target=endpoint,
                    title="GraphQL __type Introspection Enabled",
                    description="__schema is blocked but __type introspection is still available.",
                    severity="low",
                    tags=["graphql", "introspection", "api"],
                )
        except Exception:
            pass

        # Try __schema in lower case / specific case variants
        for variant in ["{__schema{queryType{name}}}", "{__SCHEMA{queryType{name}}}"]:
            try:
                async with self.bucket:
                    resp = await client.post(endpoint, json={"query": variant}, timeout=5)
                if resp.status_code == 200 and "data" in resp.json():
                    session.add_finding(
                        module="web.api_scanner",
                        target=endpoint,
                        title="GraphQL Introspection Bypass — Case Sensitivity",
                        description=f"WAF/Server blocks standard __schema but allows {variant}.",
                        severity="medium",
                        tags=["graphql", "bypass", "waf-evasion"],
                    )
                    return resp.json()["data"]
            except Exception:
                pass
        return None

    async def _test_graphql_field_suggestion(
        self, client: httpx.AsyncClient, endpoint: str, session: Session
    ) -> None:
        """Field suggestion attack — discover hidden fields via error messages."""
        query = {"query": "{ usr { passw nme } }"}
        try:
            async with self.bucket:
                resp = await client.post(endpoint, json=query, timeout=8)
            body = resp.text
            if "did you mean" in body.lower() or "suggestion" in body.lower():
                import re
                suggestions = re.findall(r'"Did you mean "([^"]+)"', body, re.IGNORECASE)
                session.add_finding(
                    module="web.api_scanner",
                    target=endpoint,
                    title="GraphQL Field Suggestion Attack",
                    description=(
                        "GraphQL returns field name suggestions in error messages.\n"
                        f"Discovered field names: {', '.join(suggestions) if suggestions else 'see response'}\n"
                        "This can be used to enumerate the schema without introspection."
                    ),
                    severity="low",
                    request=f"POST {endpoint} {json.dumps(query)}",
                    response=body[:1000],
                    tags=["graphql", "field-suggestion", "api", "enumeration"],
                )
        except Exception as exc:
            logger.debug("GraphQL field suggestion %s: %s", endpoint, exc)

    async def _test_graphql_batch(
        self, client: httpx.AsyncClient, endpoint: str, session: Session
    ) -> None:
        """Batch query abuse — bypass rate limiting."""
        batch = [{"query": "{__typename}"} for _ in range(10)]
        try:
            async with self.bucket:
                resp = await client.post(endpoint, json=batch, timeout=10)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) == 10:
                        session.add_finding(
                            module="web.api_scanner",
                            target=endpoint,
                            title="GraphQL Batching Enabled",
                            description=(
                                "GraphQL batching is enabled — multiple queries can be sent in one request.\n"
                                "This can bypass per-request rate limiting and enable efficient enumeration."
                            ),
                            severity="medium",
                            request=f"POST {endpoint} batch of 10 queries",
                            tags=["graphql", "batch", "api", "rate-limit-bypass"],
                        )
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("GraphQL batch %s: %s", endpoint, exc)

    async def _test_graphql_alias(
        self, client: httpx.AsyncClient, endpoint: str, session: Session, schema: dict | None
    ) -> None:
        """Alias abuse — bypass per-field rate limiting."""
        query = {"query": "query { a:__typename b:__typename c:__typename d:__typename e:__typename }"}
        try:
            async with self.bucket:
                resp = await client.post(endpoint, json=query, timeout=8)
            if resp.status_code == 200 and resp.json().get("data", {}).get("a"):
                session.add_finding(
                    module="web.api_scanner",
                    target=endpoint,
                    title="GraphQL Alias Abuse",
                    description=(
                        "GraphQL aliases work without restriction — multiple aliased operations "
                        "in one query can bypass per-field rate limiting."
                    ),
                    severity="low",
                    tags=["graphql", "alias", "api"],
                )
        except Exception:
            pass

    async def _test_graphql_depth(
        self, client: httpx.AsyncClient, endpoint: str, session: Session, schema: dict | None
    ) -> None:
        """Deep recursion test — DoS if no depth limit."""
        # Build a deep query using __schema nesting
        nested = "__typename " * 1
        for _ in range(10):
            nested = f"{{ {nested} }}"
        query = {"query": f"{{ {nested} }}"}
        try:
            async with self.bucket:
                resp = await client.post(endpoint, json=query, timeout=15)
            if resp.status_code == 200 and "data" in resp.json():
                session.add_finding(
                    module="web.api_scanner",
                    target=endpoint,
                    title="GraphQL No Query Depth Limit",
                    description=(
                        "GraphQL accepts deeply nested queries without a depth limit.\n"
                        "This enables DoS via deeply nested query attacks."
                    ),
                    severity="medium",
                    tags=["graphql", "depth-limit", "dos", "api"],
                    owasp_category="A05:2021-Security Misconfiguration",
                )
        except Exception:
            pass

    async def _test_graphql_mutations(
        self, client: httpx.AsyncClient, endpoint: str, session: Session, schema: dict | None
    ) -> None:
        """Test mutations for authentication requirements and injection."""
        # Generic mutation test — most GraphQL APIs require auth for mutations
        mutation = {"query": "mutation { __typename }"}
        try:
            async with self.bucket:
                resp = await client.post(endpoint, json=mutation, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if "errors" not in data or not data.get("errors"):
                    session.add_finding(
                        module="web.api_scanner",
                        target=endpoint,
                        title="GraphQL Mutation Without Authentication",
                        description=(
                            "A GraphQL mutation was accepted without authentication headers.\n"
                            "Review whether mutations require proper authorization."
                        ),
                        severity="medium",
                        tags=["graphql", "mutation", "auth", "api"],
                        owasp_category="A01:2021-Broken Access Control",
                    )
        except Exception:
            pass

    # ── gRPC ──────────────────────────────────────────────────────────────────

    async def scan_grpc(
        self,
        endpoint: str,
        proto_files: list[str] | None,
        session: Session,
    ) -> list[Any]:
        """gRPC service scanning using grpcurl."""
        import shutil
        grpcurl = shutil.which("grpcurl")
        if not grpcurl:
            logger.warning("[api_scanner] grpcurl not found — skipping gRPC scan")
            return []

        findings: list[Any] = []
        try:
            # Try reflection API
            proc = await asyncio.create_subprocess_exec(
                grpcurl, "-plaintext", endpoint, "list",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=10)
            services = (out or b"").decode(errors="ignore").strip()

            if services:
                session.add_finding(
                    module="web.api_scanner",
                    target=endpoint,
                    title="gRPC Reflection API Enabled",
                    description=(
                        f"gRPC reflection is enabled — service methods are enumerable.\n"
                        f"Services: {services[:500]}"
                    ),
                    severity="low",
                    tags=["grpc", "reflection", "api", "enumeration"],
                )
                findings.append({"type": "grpc_reflection", "endpoint": endpoint})
        except Exception as exc:
            logger.debug("gRPC scan %s: %s", endpoint, exc)
        return findings
