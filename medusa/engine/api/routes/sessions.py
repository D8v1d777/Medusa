"""Session CRUD API routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from medusa.engine.core.config import get_config
from medusa.engine.core.session import Session
from medusa.engine.core.models import SessionModel, init_db

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _get_db():
    cfg = get_config()
    return init_db(cfg.database_url)


@router.post("")
async def create_session(body: dict[str, Any]) -> dict[str, Any]:
    """Create new engagement session."""
    cfg = get_config()
    s = Session(
        cfg,
        name=body.get("name", "New Engagement"),
        operator=body.get("operator", "Analyst"),
        target=body.get("target", ""),
        scope_ips=body.get("scope_ips", []),
        scope_domains=body.get("scope_domains", []),
        scope_cidrs=body.get("scope_cidrs", []),
    )
    return {
        "id": s.id,
        "name": s.model.name,
        "operator": s.model.operator,
        "status": s.model.status,
    }


@router.get("")
async def list_sessions() -> list[dict[str, Any]]:
    """List all sessions."""
    db = _get_db()
    rows = db.query(SessionModel).order_by(SessionModel.started_at.desc()).all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "operator": r.operator,
            "target": r.target,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "status": r.status,
        }
        for r in rows
    ]


@router.get("/{session_id}")
async def get_session(session_id: str) -> dict[str, Any]:
    """Get session detail."""
    db = _get_db()
    r = db.query(SessionModel).filter_by(id=session_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "id": str(r.id),
        "name": r.name,
        "operator": r.operator,
        "target": r.target,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "status": r.status,
        "scope_ips": r.scope_ips or [],
        "scope_domains": r.scope_domains or [],
        "scope_cidrs": r.scope_cidrs or [],
    }


@router.put("/{session_id}")
async def update_session(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Update session."""
    db = _get_db()
    r = db.query(SessionModel).filter_by(id=session_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Session not found")
    if "name" in body:
        r.name = body["name"]
    if "status" in body:
        r.status = body["status"]
    db.commit()
    return {"id": str(r.id), "status": r.status}


@router.delete("/{session_id}")
async def delete_session(session_id: str) -> dict[str, str]:
    """Delete session and evidence."""
    db = _get_db()
    r = db.query(SessionModel).filter_by(id=session_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Session not found")
    db.delete(r)
    db.commit()
    return {"status": "deleted"}


@router.get("/{session_id}/stats")
async def get_session_stats(session_id: str) -> dict[str, Any]:
    """Get finding counts, duration, module status."""
    db = _get_db()
    r = db.query(SessionModel).filter_by(id=session_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Session not found")
    from medusa.engine.core.models import FindingModel
    findings = db.query(FindingModel).filter_by(session_id=session_id).all()
    by_severity = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "session_id": session_id,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "duration_seconds": None,
    }
