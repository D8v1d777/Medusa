"""
Cloud asset enumeration — TIER 4.
AWS S3, Azure Blob, GCP Storage, Firebase database discovery.
Bucket permutation + public access check.
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

__all__ = ["CloudEnum"]

logger = logging.getLogger(__name__)

# Bucket name permutation suffixes
BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-bak", "-dev", "-development", "-prod", "-production",
    "-staging", "-stage", "-test", "-testing", "-data", "-static", "-assets",
    "-media", "-uploads", "-files", "-logs", "-archive", "-archives", "-db",
    "-database", "-internal", "-private", "-public", "-web", "-app",
    "-cdn", "-images", "-videos", "-docs", "-reports", "-api",
]

BUCKET_PREFIXES = [
    "", "www-", "dev-", "prod-", "staging-", "static-", "assets-", "backup-",
    "data-", "media-", "uploads-", "files-", "internal-", "private-",
]


def _generate_bucket_names(target: str) -> list[str]:
    """Generate permutations of bucket names from a target domain/keyword."""
    # Extract base name from domain
    base = re.sub(r"\.(com|net|org|io|co|app|dev|security|edu|gov|mil)$", "", target.lower())
    base = re.sub(r"[^a-z0-9-]", "-", base)
    base = base.strip("-")

    names: set[str] = set()
    for suffix in BUCKET_SUFFIXES:
        for prefix in BUCKET_PREFIXES:
            name = f"{prefix}{base}{suffix}"
            if 3 <= len(name) <= 63:  # S3 name length constraints
                names.add(name)
    return list(names)


class CloudEnum:
    """
    Cloud asset discovery for AWS S3, Azure Blob, GCP Storage, Firebase.
    Bucket permutation + public access check.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        broadcaster: WSBroadcaster | None = None,
    ) -> None:
        self.guard = guard
        self._bucket = bucket
        self.broadcaster = broadcaster or WSBroadcaster()

    async def run(self, target_name: str, session: Session) -> None:
        """
        Enumerate cloud storage buckets for target.
        Checks AWS S3, Azure Blob, GCP, Firebase.
        """
        await self.broadcaster.log(
            session.id, "INFO",
            f"[cloud_enum] Enumerating cloud assets for: {target_name}", "cloud_enum"
        )
        await self.broadcaster.emit_progress(session.id, "cloud_enum", 0, "running")

        bucket_names = _generate_bucket_names(target_name)
        total = len(bucket_names)

        async with httpx.AsyncClient(timeout=8, follow_redirects=False,
                                     headers={"User-Agent": "Medusa-Scanner/1.0"}) as client:
            tasks = []
            for i, name in enumerate(bucket_names):
                tasks.append(self._check_all_providers(client, name, session))

            # Batch execution with concurrency limit
            semaphore = asyncio.Semaphore(20)

            async def bounded(name: str, idx: int) -> None:
                async with semaphore:
                    await self._check_all_providers(client, name, session)
                    if idx % 50 == 0:
                        pct = int((idx / max(total, 1)) * 100)
                        await self.broadcaster.emit_progress(session.id, "cloud_enum", pct, "running")

            await asyncio.gather(*[bounded(n, i) for i, n in enumerate(bucket_names)], return_exceptions=True)

        await self.broadcaster.emit_progress(session.id, "cloud_enum", 100, "done")
        await self.broadcaster.log(
            session.id, "INFO",
            f"[cloud_enum] Done. Checked {total} bucket name permutations.", "cloud_enum"
        )

    async def _check_all_providers(
        self, client: httpx.AsyncClient, name: str, session: Session
    ) -> None:
        """Check the bucket name across all providers."""
        await asyncio.gather(
            self._check_s3(client, name, session),
            self._check_azure(client, name, session),
            self._check_gcp(client, name, session),
            self._check_firebase(client, name, session),
            return_exceptions=True,
        )

    async def _check_s3(
        self, client: httpx.AsyncClient, name: str, session: Session
    ) -> None:
        """Check AWS S3 bucket."""
        urls = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
            f"https://{name}.s3.us-east-1.amazonaws.com",
        ]
        for url in urls[:1]:  # Main URL only to avoid redundant checks
            try:
                async with self._bucket:
                    resp = await client.get(url, timeout=6)

                if resp.status_code == 200:
                    content = resp.text[:500]
                    is_listing = "<ListBucketResult" in content or "<Contents>" in content
                    session.add_finding(
                        module="network.cloud_enum",
                        target=url,
                        title=f"Public S3 Bucket: {name}",
                        description=(
                            f"AWS S3 bucket '{name}' is publicly accessible.\n"
                            f"{'Directory listing enabled.' if is_listing else 'Bucket is readable.'}\n"
                            f"URL: {url}"
                        ),
                        severity="critical" if is_listing else "high",
                        request=f"GET {url}",
                        response=content,
                        tags=["cloud", "aws", "s3", "exposure", "public-bucket"],
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_ids=["CWE-732"],
                    )
                    await self.broadcaster.log(
                        session.id, "CRITICAL",
                        f"[cloud_enum] PUBLIC S3 BUCKET: {url}", "cloud_enum"
                    )

                elif resp.status_code == 403:
                    # Bucket exists but private — still noteworthy
                    session.add_finding(
                        module="network.cloud_enum",
                        target=url,
                        title=f"S3 Bucket Exists (Private): {name}",
                        description=f"AWS S3 bucket '{name}' exists but is private (403).",
                        severity="info",
                        tags=["cloud", "aws", "s3", "enumeration"],
                    )

                elif resp.status_code == 301:
                    # Redirect to regional endpoint
                    location = resp.headers.get("location", "")
                    if location:
                        try:
                            resp2 = await client.get(location, timeout=6)
                            if resp2.status_code in (200, 403):
                                severity = "high" if resp2.status_code == 200 else "info"
                                title = f"Public S3 Bucket (Regional): {name}" if resp2.status_code == 200 else f"S3 Bucket Exists (Regional): {name}"
                                session.add_finding(
                                    module="network.cloud_enum",
                                    target=location,
                                    title=title,
                                    description=f"S3 bucket '{name}' found at regional endpoint: {location}",
                                    severity=severity,
                                    tags=["cloud", "aws", "s3"],
                                )
                        except Exception:
                            pass
            except Exception as exc:
                logger.debug("S3 check %s: %s", name, exc)

    async def _check_azure(
        self, client: httpx.AsyncClient, name: str, session: Session
    ) -> None:
        """Check Azure Blob Storage containers."""
        # Azure storage account names: 3-24 lowercase alphanumeric
        azure_name = re.sub(r"[^a-z0-9]", "", name.lower())[:24]
        if len(azure_name) < 3:
            return

        services = ["blob", "file", "queue", "table"]
        for svc in services[:2]:  # Check blob and file only
            url = f"https://{azure_name}.{svc}.core.windows.net"
            try:
                async with self._bucket:
                    resp = await client.get(url, timeout=6)

                if resp.status_code == 200:
                    session.add_finding(
                        module="network.cloud_enum",
                        target=url,
                        title=f"Public Azure Blob Storage: {azure_name}",
                        description=f"Azure {svc} storage account '{azure_name}' is publicly accessible.",
                        severity="high",
                        request=f"GET {url}",
                        response=resp.text[:300],
                        tags=["cloud", "azure", "blob", "exposure"],
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                    await self.broadcaster.log(
                        session.id, "CRITICAL",
                        f"[cloud_enum] PUBLIC AZURE BLOB: {url}", "cloud_enum"
                    )

                elif resp.status_code in (403, 409, 400):
                    # Account exists
                    if svc == "blob":
                        session.add_finding(
                            module="network.cloud_enum",
                            target=url,
                            title=f"Azure Storage Account Exists: {azure_name}",
                            description=f"Azure storage account '{azure_name}' exists.",
                            severity="info",
                            tags=["cloud", "azure", "enumeration"],
                        )
            except Exception as exc:
                logger.debug("Azure check %s: %s", azure_name, exc)

    async def _check_gcp(
        self, client: httpx.AsyncClient, name: str, session: Session
    ) -> None:
        """Check GCP Cloud Storage buckets."""
        url = f"https://storage.googleapis.com/{name}"
        try:
            async with self._bucket:
                resp = await client.get(url, timeout=6)

            if resp.status_code == 200:
                session.add_finding(
                    module="network.cloud_enum",
                    target=url,
                    title=f"Public GCP Storage Bucket: {name}",
                    description=f"GCP Cloud Storage bucket '{name}' is publicly accessible.",
                    severity="critical",
                    request=f"GET {url}",
                    response=resp.text[:300],
                    tags=["cloud", "gcp", "storage", "exposure"],
                    owasp_category="A05:2021-Security Misconfiguration",
                )
                await self.broadcaster.log(
                    session.id, "CRITICAL",
                    f"[cloud_enum] PUBLIC GCP BUCKET: {url}", "cloud_enum"
                )

            elif resp.status_code == 403:
                session.add_finding(
                    module="network.cloud_enum",
                    target=url,
                    title=f"GCP Storage Bucket Exists (Private): {name}",
                    description=f"GCP bucket '{name}' exists but is private.",
                    severity="info",
                    tags=["cloud", "gcp", "enumeration"],
                )
        except Exception as exc:
            logger.debug("GCP check %s: %s", name, exc)

    async def _check_firebase(
        self, client: httpx.AsyncClient, name: str, session: Session
    ) -> None:
        """Check Firebase Realtime Database for public access."""
        url = f"https://{name}.firebaseio.com/.json"
        try:
            async with self._bucket:
                resp = await client.get(url, timeout=6)

            if resp.status_code == 200:
                data_preview = resp.text[:200]
                session.add_finding(
                    module="network.cloud_enum",
                    target=url,
                    title=f"Public Firebase Database: {name}",
                    description=(
                        f"Firebase Realtime Database '{name}' is publicly readable.\n"
                        f"Data preview: {data_preview}"
                    ),
                    severity="critical",
                    request=f"GET {url}",
                    response=data_preview,
                    tags=["cloud", "firebase", "database", "exposure", "nosql"],
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_ids=["CWE-732"],
                )
                await self.broadcaster.log(
                    session.id, "CRITICAL",
                    f"[cloud_enum] PUBLIC FIREBASE DB: {url}", "cloud_enum"
                )
        except Exception as exc:
            logger.debug("Firebase check %s: %s", name, exc)
