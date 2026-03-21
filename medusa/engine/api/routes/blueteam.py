"""Blue team API routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from medusa.engine.core.models import FindingModel, SessionModel, init_db
from medusa.engine.core.config import get_config
from medusa.engine.modules.blueteam.detection_engine import DetectionEngine
from medusa.engine.modules.blueteam.sigma_generator import SIGMAGenerator
from medusa.engine.modules.blueteam.ioc_extractor import IOCExtractor
from medusa.engine.modules.blueteam.hardening_advisor import HardeningAdvisor

router = APIRouter(prefix="/api/blueteam", tags=["blueteam"])
detection_engine = DetectionEngine()
sigma_gen = SIGMAGenerator()
ioc_extractor = IOCExtractor()
hardening_advisor = HardeningAdvisor()


def _get_db():
    return init_db(get_config().database_url)


@router.get("/{session_id}/sigma")
async def get_sigma_rules(session_id: str) -> list[dict]:
    """All SIGMA rules for session."""
    db = _get_db()
    session = db.query(SessionModel).filter_by(id=session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    findings = db.query(FindingModel).filter_by(session_id=session_id).all()
    rules = []
    for f in findings:
        det = await detection_engine.process_finding(f)
        rules.append({
            "finding_id": str(f.id),
            "sigma": sigma_gen.generate(f, det),
        })
    return rules


@router.get("/{session_id}/sigma/{siem}")
async def get_sigma_translated(session_id: str, siem: str) -> list[dict]:
    """SIGMA rules translated for specific SIEM."""
    db = _get_db()
    findings = db.query(FindingModel).filter_by(session_id=session_id).all()
    if not findings:
        raise HTTPException(status_code=404, detail="No findings")
    result = []
    for f in findings:
        det = await detection_engine.process_finding(f)
        sigma = sigma_gen.generate(f, det)
        query = sigma_gen.translate(sigma, siem)
        result.append({"finding_id": str(f.id), "query": query})
    return result


@router.get("/{session_id}/iocs")
async def get_iocs(session_id: str) -> dict:
    """IOC report."""
    db = _get_db()
    session = db.query(SessionModel).filter_by(id=session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    report = await ioc_extractor.extract(session)
    return {
        "session_id": report.session_id,
        "network": [{"type": e.type, "value": e.value, "source": e.source_finding_id} for e in report.network],
        "web": [{"type": e.type, "value": e.value, "source": e.source_finding_id} for e in report.web],
        "credential": [{"type": e.type, "value": e.value[:8] + "..."} for e in report.credential],
    }


@router.get("/{session_id}/iocs/stix")
async def get_iocs_stix(session_id: str) -> Response:
    """STIX 2.1 export."""
    db = _get_db()
    session = db.query(SessionModel).filter_by(id=session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    report = await ioc_extractor.extract(session)
    stix = {
        "type": "bundle",
        "id": "bundle--medusa-export",
        "objects": [
            {"type": "indicator", "id": f"indicator--{i}", "pattern": f"[ipv4-addr:value = '{e.value}']"}
            for i, e in enumerate(report.network[:100])
        ],
    }
    import json
    return Response(content=json.dumps(stix, indent=2), media_type="application/json")


@router.get("/{session_id}/hardening")
async def get_hardening(session_id: str) -> dict:
    """Hardening report."""
    db = _get_db()
    session = db.query(SessionModel).filter_by(id=session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    findings = db.query(FindingModel).filter_by(session_id=session_id).all()
    report = await hardening_advisor.advise(findings, session)
    return {
        "session_id": report.session_id,
        "items": [
            {
                "category": i.category,
                "title": i.title,
                "finding_ids": i.finding_ids,
                "recommended_control": i.recommended_control,
                "implementation_effort": i.implementation_effort,
                "priority_score": i.priority_score,
            }
            for i in report.items
        ],
    }


@router.get("/{session_id}/hardening/pdf")
async def get_hardening_pdf(session_id: str) -> Response:
    """PDF hardening report."""
    db = _get_db()
    session = db.query(SessionModel).filter_by(id=session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    findings = db.query(FindingModel).filter_by(session_id=session_id).all()
    report = await hardening_advisor.advise(findings, session)
    html = f"<html><body><h1>Hardening Report - {session.name}</h1>"
    for i in report.items:
        html += f"<h2>{i.category}: {i.title}</h2><p>{i.recommended_control}</p>"
    html += "</body></html>"
    return Response(content=html, media_type="text/html")
