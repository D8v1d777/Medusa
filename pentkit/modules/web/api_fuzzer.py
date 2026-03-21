from __future__ import annotations
import httpx
import yaml
import json
import asyncio
import logging
from typing import List, Dict, Optional
from pentkit.core.session import Session
from pentkit.core.logger import get_module_logger
from pentkit.core.rate_limiter import TokenBucket
from pentkit.core.ai_engine import AIEngine

logger = get_module_logger("web.api_fuzzer")

class APIFuzzer:
    """Discovers and fuzzes API endpoints (REST/GraphQL)."""
    
    def __init__(self, bucket: TokenBucket, ai: AIEngine):
        self.bucket = bucket
        self.ai = ai
        self.discovery_paths = [
            "/openapi.json", "/swagger.json", "/api-docs", "/v1/api-docs", 
            "/api/v1/swagger.json", "/v2/api-docs", "/api/v2/swagger.json"
        ]

    async def _discover_spec(self, target: str) -> Optional[Dict]:
        """Try to auto-discover OpenAPI spec from common paths."""
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for path in self.discovery_paths:
                url = target.rstrip('/') + path
                try:
                    async with self.bucket:
                        response = await client.get(url)
                        if response.status_code == 200:
                            try:
                                spec = response.json()
                                logger.info(f"Discovered OpenAPI spec at {url}", extra={"pentkit_module": "web.api_fuzzer", "target": target})
                                return spec
                            except json.JSONDecodeError:
                                # Try YAML
                                try:
                                    spec = yaml.safe_load(response.text)
                                    logger.info(f"Discovered OpenAPI spec at {url} (YAML)", extra={"pentkit_module": "web.api_fuzzer", "target": target})
                                    return spec
                                except yaml.YAMLError:
                                    continue
                except Exception as e:
                    logger.debug(f"Discovery check failed for {url}: {e}")
        return None

    async def _test_mass_assignment(self, url: str, method: str, params: Dict, session: Session):
        """Test for mass assignment by adding sensitive parameters."""
        sensitive_params = {"isAdmin": True, "role": "admin", "price": 0.0, "credits": 99999}
        test_params = {**params, **sensitive_params}
        
        async with self.bucket:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                try:
                    if method == 'post':
                        response = await client.post(url, json=test_params)
                    elif method == 'put':
                        response = await client.put(url, json=test_params)
                    else:
                        return
                    
                    if response.status_code in [200, 201]:
                        # A success code doesn't always mean a vulnerability, but it's suspicious.
                        # In a concise tool, we report it for operator review.
                        session.add_finding(
                            module="web.api_fuzzer",
                            target=url,
                            title="Potential Mass Assignment",
                            description="The API accepted sensitive parameters (e.g., isAdmin, role) in a POST/PUT request.",
                            severity="medium",
                            payload=json.dumps(sensitive_params),
                            response=f"HTTP {response.status_code}",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            tags=["api", "mass-assignment"]
                        )
                except Exception as e:
                    logger.debug(f"Mass assignment test failed for {url}: {e}"  )

    async def _test_graphql_introspection(self, target: str, session: Session):
        """Test for GraphQL introspection."""
        gql_paths = ["/graphql", "/gql", "/api/graphql", "/v1/graphql"]
        query = '{"query": "{__schema{types{name,fields{name}}}}"}'
        
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for path in gql_paths:
                url = target.rstrip('/') + path
                try:
                    async with self.bucket:
                        response = await client.post(url, data=query, headers={"Content-Type": "application/json"})
                        if response.status_code == 200 and "__schema" in response.text:
                            session.add_finding(
                                module="web.api_fuzzer",
                                target=url,
                                title="GraphQL Introspection Enabled",
                                description="Enabled introspection allows schema extraction, potentially exposing sensitive data structures.",
                                severity="low",
                                payload=query,
                                response=response.text[:500],
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                tags=["api", "graphql"]
                            )
                except Exception as e:
                    logger.debug(f"GraphQL check failed for {url}: {e}")

    async def run(self, target: str, session: Session, spec: Optional[Dict] = None):
        """Execute API discovery and testing."""
        if not spec:
            spec = await self._discover_spec(target)
        
        if spec:
            # Concise parsing of endpoints from spec (if needed)
            pass
        
        await self._test_graphql_introspection(target, session)

__all__ = ["APIFuzzer"]
