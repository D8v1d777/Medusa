"""Findings API routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from medusa.engine.core.models import FindingModel, init_db
from medusa.engine.core.config import get_config

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _get_db():
    return init_db(get_config().database_url)


def _finding_to_dict(f: FindingModel) -> dict:
    return {
        "id": str(f.id),
        "session_id": str(f.session_id),
        "ts": f.ts.isoformat() if f.ts else None,
        "module": f.module,
        "target": f.target,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "cvss_vector": f.cvss_vector,
        "cvss_score": f.cvss_score,
        "payload": f.payload,
        "request": f.request,
        "response": f.response,
        "confidence": f.confidence,
        "verified": f.verified,
        "cve_ids": f.cve_ids or [],
        "tags": f.tags or [],
    }


@router.get("")
async def list_findings(
    session_id: str | None = Query(None),
    severity: str | None = Query(None),
    module: str | None = Query(None),
    verified: str | None = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
) -> dict:
    """List findings with filters."""
    db = _get_db()
    q = db.query(FindingModel)
    if session_id:
        q = q.filter(FindingModel.session_id == session_id)
    if severity:
        q = q.filter(FindingModel.severity == severity)
    if module:
        q = q.filter(FindingModel.module == module)
    if verified:
        q = q.filter(FindingModel.verified == verified)
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "findings": [_finding_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/{finding_id}")
async def get_finding(finding_id: str) -> dict:
    """Get full finding detail."""
    db = _get_db()
    f = db.query(FindingModel).filter_by(id=finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_to_dict(f)


@router.put("/{finding_id}")
async def update_finding(finding_id: str, body: dict) -> dict:
    """Update finding (notes, severity)."""
    db = _get_db()
    f = db.query(FindingModel).filter_by(id=finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    if "severity" in body:
        f.severity = body["severity"]
    if "details" in body:
        f.details = {**(f.details or {}), **body["details"]}
    db.commit()
    return _finding_to_dict(f)


@router.get("/{finding_id}/detection")
async def get_finding_detection(finding_id: str) -> dict:
    """Get blue team artifact for this finding."""
    return {"sigma_rule": None, "yara_rule": None, "iocs": []}


@router.post("/{finding_id}/verify")
async def verify_finding(finding_id: str) -> dict:
    """Trigger manual re-verification."""
    return {"status": "pending", "finding_id": finding_id}
