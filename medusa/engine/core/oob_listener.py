"""OOB (Out-of-Band) listener — Interactsh, ngrok, timing fallback."""
from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import time
from typing import Any, Callable, Literal

import httpx
from pydantic import BaseModel

__all__ = ["OOBOrchestrator", "OOBProfile", "OOBInteraction", "CallbackQueue"]

logger = logging.getLogger(__name__)


class OOBInteraction(BaseModel):
    """Single OOB callback interaction."""

    protocol: str
    source_ip: str
    data: str
    timestamp: str


class OOBProfile(BaseModel):
    """OOB channel profile."""

    http_url: str | None = None
    dns_domain: str | None = None
    smtp_address: str | None = None
    channel: Literal["interactsh", "collaborator", "ngrok", "dns", "timing"]
    poll_fn: Callable | None = None
    config: dict[str, Any] = {}


class CallbackQueue:
    """Persistent queue for OOB callbacks. Matches late-arriving callbacks."""

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        self._pending: dict[str, dict[str, Any]] = {}
        self._matched: dict[str, OOBInteraction] = {}

    async def register(
        self,
        finding_id: str,
        payload_url: str,
        expected_protocols: list[str] | None = None,
        ttl_minutes: int = 60,
    ) -> None:
        """Register a finding as expecting an OOB callback."""
        self._pending[finding_id] = {
            "payload_url": payload_url,
            "registered_ts": time.time(),
            "ttl_minutes": ttl_minutes,
            "expected_protocols": expected_protocols or [],
            "matched": False,
        }

    async def match(self, interaction: OOBInteraction) -> str | None:
        """Match interaction to pending finding. Returns finding_id if matched."""
        for fid, meta in self._pending.items():
            if meta.get("matched"):
                continue
            if fid in (interaction.data or "") or fid in (interaction.source_ip or ""):
                meta["matched"] = True
                self._matched[fid] = interaction
                return fid
        return None


class OOBOrchestrator:
    """Manages multiple OOB channels. Priority: Interactsh, ngrok, timing."""

    def __init__(self) -> None:
        self.interactsh_token: str | None = None
        self.interactsh_secret: str | None = None
        self.interactsh_domain: str | None = None
        self.ngrok_process: subprocess.Popen | None = None
        self.ngrok_url: str | None = None
        self.callback_queue = CallbackQueue()
        self.active_profile: OOBProfile | None = None

    async def setup(self, session_id: str = "") -> OOBProfile:
        """Establish OOB infrastructure in priority order."""
        self.callback_queue.session_id = session_id

        profile = await self._setup_interactsh()
        if profile:
            logger.info("OOB channel: Interactsh")
            self.active_profile = profile
            return profile

        profile = await self._setup_ngrok()
        if profile:
            logger.info("OOB channel: ngrok")
            self.active_profile = profile
            return profile

        profile = OOBProfile(channel="timing")
        self.active_profile = profile
        logger.info("OOB channel: timing (fallback)")
        return profile

    async def _setup_interactsh(self) -> OOBProfile | None:
        """Register with Interactsh API."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    "https://app.interactsh.com/api/v1/register", json={}
                )
                if response.status_code == 200:
                    data = response.json()
                    self.interactsh_token = data.get("token", data.get("id", ""))
                    self.interactsh_secret = data.get("secret", "")
                    domain = data.get("server", "oast.fun")
                    self.interactsh_domain = f"{self.interactsh_token}.{domain}"

                    return OOBProfile(
                        http_url=f"http://{self.interactsh_domain}",
                        dns_domain=self.interactsh_domain,
                        channel="interactsh",
                        poll_fn=self._poll_interactsh,
                    )
        except Exception as e:
            logger.debug("Interactsh setup failed: %s", e)
        return None

    async def _poll_interactsh(self) -> list[OOBInteraction]:
        """Poll Interactsh for interactions."""
        if not self.interactsh_token or not self.interactsh_secret:
            return []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                url = f"https://app.interactsh.com/api/v1/poll?id={self.interactsh_token}&secret={self.interactsh_secret}"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    interactions = []
                    for item in data.get("data", data.get("interactions", [])):
                        interactions.append(
                            OOBInteraction(
                                protocol=item.get("protocol", "http"),
                                source_ip=item.get("remote-address", item.get("source_ip", "")),
                                data=item.get("raw-request", item.get("data", "")),
                                timestamp=item.get("timestamp", str(time.time())),
                            )
                        )
                    return interactions
        except Exception:
            pass
        return []

    async def _setup_ngrok(self) -> OOBProfile | None:
        """Set up ngrok tunnel."""
        if not shutil.which("ngrok"):
            return None
        try:
            port = 45678
            self.ngrok_process = subprocess.Popen(
                ["ngrok", "http", str(port), "--log=stdout"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(5)
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:4040/api/tunnels")
                if response.status_code == 200:
                    data = response.json()
                    tunnels = data.get("tunnels", [])
                    if tunnels:
                        self.ngrok_url = tunnels[0].get("public_url", "")
                        return OOBProfile(
                            http_url=self.ngrok_url,
                            channel="ngrok",
                        )
        except Exception:
            if self.ngrok_process:
                self.ngrok_process.terminate()
        return None
