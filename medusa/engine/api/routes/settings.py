"""Settings API routes."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings() -> dict:
    """Get current settings."""
    return {"theme": "dark", "rate_limit": 5}


@router.put("")
async def update_settings(body: dict) -> dict:
    """Update settings."""
    return {"status": "ok"}
