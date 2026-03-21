"""WebSocket — live scan output stream."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from medusa.engine.core.ws_broadcaster import WSBroadcaster

router = APIRouter(tags=["websocket"])
logger = logging.getLogger(__name__)


@router.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str) -> None:
    """Live scan output stream for session."""
    await websocket.accept()
    broadcaster = WSBroadcaster()
    queue = broadcaster.subscribe(session_id)
    try:
        while True:
            msg = await queue.get()
            await websocket.send_text(json.dumps(msg))
    except WebSocketDisconnect:
        broadcaster.unsubscribe(session_id, queue)
    except Exception as e:
        logger.debug("WebSocket error: %s", e)
        broadcaster.unsubscribe(session_id, queue)
