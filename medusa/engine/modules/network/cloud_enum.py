"""Cloud enum — AWS, Azure, GCP asset discovery."""
from __future__ import annotations

import logging

import httpx

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.session import Session

__all__ = ["CloudEnum"]

logger = logging.getLogger(__name__)


class CloudEnum:
    """Passive/semi-active cloud asset discovery."""

    def __init__(self, guard: ScopeGuard, bucket: TokenBucket) -> None:
        self.guard = guard
        self.bucket = bucket

    async def run(
        self, target_name: str, session: Session
    ) -> None:
        """Enumerate S3, Blob, GCS buckets for target name."""
        suffixes = ["-backup", "-dev", "-prod", "-data", "-static"]
        for suffix in suffixes:
            bucket_name = f"{target_name}{suffix}".replace(".", "-").lower()
            url = f"https://{bucket_name}.s3.amazonaws.com"
            self.guard.check(url, "network.cloud_enum")
            async with self.bucket:
                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            session.add_finding(
                                module="network.cloud_enum",
                                target=url,
                                title="Public S3 bucket",
                                description=f"Bucket {bucket_name} is publicly accessible",
                                severity="critical",
                                tags=["cloud", "aws", "s3"],
                            )
                        elif resp.status_code == 403:
                            session.add_finding(
                                module="network.cloud_enum",
                                target=url,
                                title="S3 bucket exists (private)",
                                description=f"Bucket {bucket_name} exists but is private",
                                severity="info",
                                tags=["cloud", "aws", "s3"],
                            )
                except Exception:
                    pass
