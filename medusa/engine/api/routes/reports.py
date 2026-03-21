"""Reports API routes."""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse

from medusa.engine.core.models import SessionModel, init_db
from medusa.engine.core.config import get_config
from medusa.engine.output.report_engine import ReportEngine
from medusa.engine.core.session import Session

router = APIRouter(prefix="/api/reports", tags=["reports"])
_report_cache: dict[str, str] = {}


def _get_db():
    return init_db(get_config().database_url)


@router.post("/generate")
async def generate_report(body: dict) -> dict:
    """Start AI report generation."""
    session_id = body.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    db = _get_db()
    session_model = db.query(SessionModel).filter_by(id=session_id).first()
    if not session_model:
        raise HTTPException(status_code=404, detail="Session not found")
    cfg = get_config()
    s = Session(cfg, session_id=session_id)
    engine = ReportEngine(s)
    html = await engine.render_executive()
    _report_cache[session_id] = html
    return {"id": session_id, "status": "generated"}


@router.get("/{report_id}/stream")
async def stream_report(report_id: str):
    """SSE stream of report text."""
    html = _report_cache.get(report_id, "")
    async def gen():
        for chunk in [html[i:i+100] for i in range(0, len(html), 100)]:
            yield f"data: {json.dumps({'text': chunk})}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/{report_id}/pdf")
async def get_report_pdf(report_id: str) -> HTMLResponse:
    """Download report as PDF (returns HTML for now)."""
    html = _report_cache.get(report_id, "<html><body>No report</body></html>")
    return HTMLResponse(content=html)


@router.get("/{report_id}/html")
async def get_report_html(report_id: str) -> HTMLResponse:
    """Download report HTML."""
    html = _report_cache.get(report_id, "<html><body>No report</body></html>")
    return HTMLResponse(content=html)
