"""WebSocket broadcaster — singleton for live scan output to GUI."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

__all__ = ["WSBroadcaster"]

logger = logging.getLogger(__name__)


class WSBroadcaster:
    """
    Singleton. Every module calls this to emit output.
    Frontend Xterm.js receives it and displays in real time.
    """

    _instance: "WSBroadcaster | None" = None
    _lock = asyncio.Lock()

    def __new__(cls) -> "WSBroadcaster":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, "_initialized") and self._initialized:
            return
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self._initialized = True

    def _ansi_color(self, level: str) -> str:
        """ANSI codes for Xterm.js colour coding."""
        codes = {
            "DEBUG": "\033[2;37m",
            "INFO": "\033[0;37m",
            "SUCCESS": "\033[0;32m",
            "WARNING": "\033[0;33m",
            "ERROR": "\033[0;31m",
            "CRITICAL": "\033[1;31m",
        }
        return codes.get(level, "\033[0;37m")

    def subscribe(self, session_id: str) -> asyncio.Queue:
        """Subscribe to session messages. Returns a queue."""
        queue: asyncio.Queue = asyncio.Queue()
        if session_id not in self._subscribers:
            self._subscribers[session_id] = []
        self._subscribers[session_id].append(queue)
        return queue

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        """Unsubscribe from session messages."""
        if session_id in self._subscribers:
            try:
                self._subscribers[session_id].remove(queue)
            except ValueError:
                pass

    async def _broadcast(self, session_id: str, msg: dict[str, Any]) -> None:
        """Send message to all subscribers of the session."""
        if session_id not in self._subscribers:
            return
        dead = []
        for q in self._subscribers[session_id]:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(session_id, q)

    async def log(
        self, session_id: str, level: str, message: str, module: str
    ) -> None:
        """
        Broadcast a log line to all connected WebSocket clients for this session.
        Colour codes: DEBUG (dim), INFO (white), SUCCESS (green), WARNING (yellow),
        ERROR (red), CRITICAL (bright red bold).
        """
        await self._broadcast(
            session_id,
            {
                "type": "log",
                "data": {
                    "level": level,
                    "message": message,
                    "module": module,
                    "ansi": f"{self._ansi_color(level)}{message}\033[0m",
                },
            },
        )

    async def emit_finding(self, session_id: str, finding: Any) -> None:
        """Broadcast a new finding. Frontend adds to live findings feed."""
        data = finding
        if hasattr(finding, "model_dump"):
            data = finding.model_dump()
        elif hasattr(finding, "__dict__"):
            data = {k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v for k, v in finding.__dict__.items()}
        await self._broadcast(session_id, {"type": "finding", "data": data})

    async def emit_progress(
        self, session_id: str, module: str, percent: int, status: str = "running"
    ) -> None:
        """Update module progress bar in ScanControl left panel."""
        await self._broadcast(
            session_id,
            {
                "type": "progress",
                "data": {"module": module, "percent": percent, "status": status},
            },
        )
