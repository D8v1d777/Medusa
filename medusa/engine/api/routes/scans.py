"""Scan control API routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/scans", tags=["scans"])

# In-memory scan state for Phase 2; will be replaced with proper scan orchestration
_scan_state: dict[str, dict] = {}


@router.post("/start")
async def start_scan(body: dict) -> dict:
    """Start scan. Body: session_id, modules[]."""
    session_id = body.get("session_id")
    modules = body.get("modules", [])
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    _scan_state[session_id] = {"status": "running", "modules": modules}
    return {"status": "started", "session_id": session_id}


@router.post("/{session_id}/pause")
async def pause_scan(session_id: str) -> dict:
    """Pause running scan."""
    if session_id not in _scan_state:
        raise HTTPException(status_code=404, detail="Scan not found")
    _scan_state[session_id]["status"] = "paused"
    return {"status": "paused"}


@router.post("/{session_id}/resume")
async def resume_scan(session_id: str) -> dict:
    """Resume paused scan."""
    if session_id not in _scan_state:
        raise HTTPException(status_code=404, detail="Scan not found")
    _scan_state[session_id]["status"] = "running"
    return {"status": "resumed"}


@router.post("/{session_id}/stop")
async def stop_scan(session_id: str) -> dict:
    """Stop scan gracefully."""
    if session_id not in _scan_state:
        raise HTTPException(status_code=404, detail="Scan not found")
    _scan_state[session_id]["status"] = "stopped"
    return {"status": "stopped"}


@router.get("/{session_id}/status")
async def get_scan_status(session_id: str) -> dict:
    """Get module status and progress."""
    if session_id not in _scan_state:
        return {"status": "idle", "modules": []}
    return _scan_state[session_id]
