"""
Scan control API routes — fully wired to ActiveScanner, TemplateEngine, NetworkScanner.
POST /api/scans/start           — Start a full active scan
POST /api/scans/templates/run   — Run Nuclei templates (PHASE 2)
POST /api/scans/network/run     — Run network scan
POST /api/scans/cloud/run       — Run cloud asset discovery
POST /api/scans/{id}/pause      — Pause
POST /api/scans/{id}/resume     — Resume
POST /api/scans/{id}/stop       — Stop
GET  /api/scans/{id}/status     — Status + progress
GET  /api/scans/templates/search — Search template library
POST /api/scans/templates/update — Update template library
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])

# In-memory scan state
_scan_state: dict[str, dict[str, Any]] = {}
_scan_tasks: dict[str, asyncio.Task] = {}


# ── Request models ─────────────────────────────────────────────────────────────

class StartScanRequest(BaseModel):
    session_id: str
    target: str
    policy: str = "standard"
    modules: list[str] = []
    auth_method: str = "none"
    auth_credentials: dict[str, str] = {}


class TemplateRunRequest(BaseModel):
    session_id: str
    target: str
    categories: list[str] | None = None
    severities: list[str] | None = None
    tags: list[str] | None = None
    cve_ids: list[str] | None = None
    concurrency: int = 50
    rate_limit: int = 150
    template_path: str | None = None  # custom single template


class NetworkScanRequest(BaseModel):
    session_id: str
    target: str


class CloudScanRequest(BaseModel):
    session_id: str
    target_name: str


class TemplateSearchRequest(BaseModel):
    query: str = ""
    category: str | None = None
    severity: str | None = None
    cve_id: str | None = None
    tag: str | None = None


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _get_cfg_and_session(session_id: str):
    """Load config and session from DB."""
    from medusa.engine.core.config import Config
    from medusa.engine.core.session import Session
    cfg = Config()
    session = Session(cfg, session_id=session_id)
    return cfg, session


def _set_state(session_id: str, status: str, **kwargs: Any) -> None:
    if session_id not in _scan_state:
        _scan_state[session_id] = {}
    _scan_state[session_id].update({"status": status, **kwargs})


# ── Active Scan ────────────────────────────────────────────────────────────────

@router.post("/start")
async def start_scan(body: StartScanRequest, bg: BackgroundTasks) -> dict:
    """Start a full active scan using the specified policy."""
    session_id = body.session_id
    _set_state(session_id, "starting", target=body.target, policy=body.policy)

    async def _run() -> None:
        try:
            from medusa.engine.core.config import Config
            from medusa.engine.core.session import Session
            from medusa.engine.core.scope_guard import ScopeGuard
            from medusa.engine.core.rate_limiter import TokenBucket
            from medusa.engine.core.ws_broadcaster import WSBroadcaster
            from medusa.engine.modules.web.active_scanner import ActiveScanner
            from medusa.engine.modules.web.authenticated_scanner import (
                AuthenticatedScanner, AuthCredentials
            )

            cfg = Config()
            session = Session(cfg, session_id=session_id)
            broadcaster = WSBroadcaster()
            guard = ScopeGuard(cfg.scope)
            bucket = TokenBucket(rate=50, capacity=100)

            _set_state(session_id, "running")

            # Authenticate if requested
            auth_context = None
            if body.auth_method and body.auth_method != "none":
                auth_scanner = AuthenticatedScanner(broadcaster)
                creds = AuthCredentials(**{
                    k: v for k, v in body.auth_credentials.items()
                    if hasattr(AuthCredentials, k)
                })
                auth_context = await auth_scanner.authenticate(
                    body.target, body.auth_method, creds, session
                )

            # Run active scan
            scanner = ActiveScanner(guard, bucket, broadcaster)
            result = await scanner.run(
                target=body.target,
                policy=body.policy,
                auth_context=auth_context,
                session=session,
            )

            _set_state(session_id, "complete",
                       total_findings=result.total_findings,
                       modules_run=result.modules_run,
                       duration=result.scan_duration,
                       coverage_score=result.coverage_score)
        except Exception as exc:
            logger.error("Scan error for %s: %s", session_id, exc)
            _set_state(session_id, "error", error=str(exc))

    task = asyncio.create_task(_run())
    _scan_tasks[session_id] = task
    return {"status": "started", "session_id": session_id, "policy": body.policy}


# ── Template Engine ────────────────────────────────────────────────────────────

@router.post("/templates/run")
async def run_templates(body: TemplateRunRequest) -> dict:
    """
    Run Nuclei templates against a target.
    Wire: POST /api/scans/templates/run → TemplateEngine.run()
    """
    _set_state(body.session_id, "running", module="template_engine")

    async def _run() -> None:
        try:
            from medusa.engine.core.config import Config
            from medusa.engine.core.session import Session
            from medusa.engine.core.ws_broadcaster import WSBroadcaster
            from medusa.engine.modules.web.template_engine import TemplateEngine

            cfg = Config()
            session = Session(cfg, session_id=body.session_id)
            te = TemplateEngine(WSBroadcaster())

            if body.template_path:
                findings = await te.run_custom_template(body.target, body.template_path, session)
            else:
                findings = await te.run(
                    target=body.target,
                    session=session,
                    categories=body.categories,
                    severities=body.severities,
                    tags=body.tags,
                    cve_ids=body.cve_ids,
                    concurrency=body.concurrency,
                    rate_limit=body.rate_limit,
                )
            _set_state(body.session_id, "complete",
                       total_findings=len(findings), module="template_engine")
        except Exception as exc:
            logger.error("Template run error: %s", exc)
            _set_state(body.session_id, "error", error=str(exc))

    asyncio.create_task(_run())
    return {"status": "started", "session_id": body.session_id, "target": body.target}


@router.get("/templates/search")
async def search_templates(
    query: str = "",
    category: str | None = None,
    severity: str | None = None,
    cve_id: str | None = None,
    tag: str | None = None,
) -> dict:
    """Search template library with FTS."""
    try:
        from medusa.engine.modules.web.template_engine import TemplateEngine
        te = TemplateEngine()
        results = te.search_templates(
            query=query, category=category, severity=severity,
            cve_id=cve_id, tag=tag
        )
        return {
            "count": len(results),
            "templates": [
                {
                    "id": t.id, "name": t.name, "severity": t.severity,
                    "category": t.category, "tags": t.tags, "cve_ids": t.cve_ids,
                    "description": t.description, "author": t.author, "path": t.path,
                }
                for t in results
            ]
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/templates/update")
async def update_templates() -> dict:
    """Update template library from nuclei community templates."""
    try:
        from medusa.engine.modules.web.template_engine import TemplateEngine
        te = TemplateEngine()
        stats = await te.update_templates()
        return {
            "status": "updated",
            "total_templates": stats.total_templates,
            "by_severity": stats.by_severity,
            "by_category": stats.by_category,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/templates/setup")
async def setup_templates() -> dict:
    """First-launch setup: install nuclei + download templates."""
    try:
        from medusa.engine.modules.web.template_engine import TemplateEngine
        te = TemplateEngine()
        stats = await te.setup()
        return {
            "status": "ready",
            "total_templates": stats.total_templates,
            "by_severity": stats.by_severity,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/templates/create")
async def create_template(body: dict) -> dict:
    """AI-assisted custom template creation."""
    try:
        from medusa.engine.modules.web.template_engine import TemplateEngine
        te = TemplateEngine()
        path = await te.create_template(
            name=body.get("name", "custom-template"),
            description=body.get("description", ""),
            target_url_pattern=body.get("target_url_pattern", ""),
            detection_logic=body.get("detection_logic", ""),
            severity=body.get("severity", "medium"),
            tags=body.get("tags", []),
        )
        return {"status": "created", "path": path}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Network Scan ───────────────────────────────────────────────────────────────

@router.post("/network/run")
async def run_network_scan(body: NetworkScanRequest) -> dict:
    """Run network port scan + CVE correlation."""
    _set_state(body.session_id, "running", module="network.scanner")

    async def _run() -> None:
        try:
            from medusa.engine.core.config import Config
            from medusa.engine.core.session import Session
            from medusa.engine.core.scope_guard import ScopeGuard
            from medusa.engine.core.rate_limiter import TokenBucket
            from medusa.engine.core.ws_broadcaster import WSBroadcaster
            from medusa.engine.modules.network.scanner import NetworkScanner

            cfg = Config()
            session = Session(cfg, session_id=body.session_id)
            guard = ScopeGuard(cfg.scope)
            bucket = TokenBucket(rate=20, capacity=50)
            scanner = NetworkScanner(guard, bucket, WSBroadcaster())
            profiles = await scanner.run(body.target, session)
            _set_state(body.session_id, "complete",
                       hosts=len(profiles),
                       total_ports=sum(len(h.ports) for h in profiles))
        except Exception as exc:
            logger.error("Network scan error: %s", exc)
            _set_state(body.session_id, "error", error=str(exc))

    asyncio.create_task(_run())
    return {"status": "started", "session_id": body.session_id}


# ── Cloud Enum ─────────────────────────────────────────────────────────────────

@router.post("/cloud/run")
async def run_cloud_enum(body: CloudScanRequest) -> dict:
    """Run cloud asset discovery."""
    _set_state(body.session_id, "running", module="cloud_enum")

    async def _run() -> None:
        try:
            from medusa.engine.core.config import Config
            from medusa.engine.core.session import Session
            from medusa.engine.core.scope_guard import ScopeGuard
            from medusa.engine.core.rate_limiter import TokenBucket
            from medusa.engine.core.ws_broadcaster import WSBroadcaster
            from medusa.engine.modules.network.cloud_enum import CloudEnum

            cfg = Config()
            session = Session(cfg, session_id=body.session_id)
            guard = ScopeGuard(cfg.scope)
            bucket = TokenBucket(rate=30, capacity=60)
            ce = CloudEnum(guard, bucket, WSBroadcaster())
            await ce.run(body.target_name, session)
            _set_state(body.session_id, "complete", module="cloud_enum")
        except Exception as exc:
            logger.error("Cloud enum error: %s", exc)
            _set_state(body.session_id, "error", error=str(exc))

    asyncio.create_task(_run())
    return {"status": "started", "session_id": body.session_id}


# ── Passive Scanner ────────────────────────────────────────────────────────────

@router.post("/passive/proxy/start")
async def start_proxy(body: dict) -> dict:
    """Start intercepting proxy for passive analysis."""
    session_id = body.get("session_id", "")
    port = int(body.get("port", 8888))
    try:
        from medusa.engine.core.config import Config
        from medusa.engine.core.session import Session
        from medusa.engine.core.ws_broadcaster import WSBroadcaster
        from medusa.engine.modules.web.passive_scanner import PassiveScanner

        cfg = Config()
        session = Session(cfg, session_id=session_id) if session_id else None
        ps = PassiveScanner(WSBroadcaster())
        proxy_info = await ps.start_proxy(port=port, session=session)
        return {
            "status": "running",
            "host": proxy_info.host,
            "port": proxy_info.port,
            "ca_cert_path": proxy_info.ca_cert_path,
            "instruction": f"Configure your browser to use proxy: {proxy_info.host}:{proxy_info.port}",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/passive/har")
async def analyse_har(body: dict) -> dict:
    """Analyse a HAR file passively."""
    session_id = body.get("session_id", "")
    har_path = body.get("har_path", "")
    if not har_path:
        raise HTTPException(status_code=400, detail="har_path required")
    try:
        from medusa.engine.core.config import Config
        from medusa.engine.core.session import Session
        from medusa.engine.core.ws_broadcaster import WSBroadcaster
        from medusa.engine.modules.web.passive_scanner import PassiveScanner

        cfg = Config()
        session = Session(cfg, session_id=session_id)
        ps = PassiveScanner(WSBroadcaster())
        findings = await ps.analyse_har(har_path, session)
        return {"status": "complete", "total_findings": len(findings)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── AI Routes ──────────────────────────────────────────────────────────────────

@router.post("/ai/triage/{session_id}")
async def run_ai_triage(session_id: str) -> dict:
    """Run AI triage on all session findings."""
    try:
        from medusa.engine.core.config import Config
        from medusa.engine.core.session import Session
        from medusa.engine.core.models import FindingModel
        from medusa.engine.modules.ai.triage import AITriage

        cfg = Config()
        session = Session(cfg, session_id=session_id)
        findings = session.db_session.query(FindingModel).filter_by(session_id=session_id).all()
        triage = AITriage()
        results = await triage.run(findings, session)
        fp_count = sum(1 for r in results if r.assessment.is_false_positive)
        return {
            "total_triaged": len(results),
            "false_positives_removed": fp_count,
            "confirmed": len(results) - fp_count,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/ai/chains/{session_id}")
async def build_attack_chains(session_id: str) -> dict:
    """Build AI attack chains for session findings."""
    try:
        from medusa.engine.core.config import Config
        from medusa.engine.core.session import Session
        from medusa.engine.modules.ai.chain_builder import suggest_chains

        cfg = Config()
        session = Session(cfg, session_id=session_id)
        chains = await suggest_chains(session)
        return {
            "total_chains": len(chains),
            "chains": [
                {
                    "name": c.name,
                    "objective": c.objective,
                    "mitre_techniques": c.mitre_techniques,
                    "likelihood": c.likelihood,
                    "impact": c.impact,
                    "steps": [
                        {"finding_id": s.finding_id, "action": s.action, "outcome": s.outcome}
                        for s in c.steps
                    ],
                }
                for c in chains
            ],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Scan control ──────────────────────────────────────────────────────────────

@router.post("/{session_id}/pause")
async def pause_scan(session_id: str) -> dict:
    _set_state(session_id, "paused")
    return {"status": "paused"}


@router.post("/{session_id}/resume")
async def resume_scan(session_id: str) -> dict:
    _set_state(session_id, "running")
    return {"status": "resumed"}


@router.post("/{session_id}/stop")
async def stop_scan(session_id: str) -> dict:
    task = _scan_tasks.get(session_id)
    if task and not task.done():
        task.cancel()
    _set_state(session_id, "stopped")
    return {"status": "stopped"}


@router.get("/{session_id}/status")
async def get_scan_status(session_id: str) -> dict:
    if session_id not in _scan_state:
        return {"status": "idle", "session_id": session_id}
    return {"session_id": session_id, **_scan_state[session_id]}
