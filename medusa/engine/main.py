"""FastAPI app entry — Medusa Engine."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from medusa.engine.api.routes import sessions, scans, findings, blueteam, reports, settings
from medusa.engine.api.websocket import router as ws_router

app = FastAPI(
    title="Engine",
    version="5.0.0",
    description="Assessment framework backend",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sessions.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(blueteam.router)
app.include_router(reports.router)
app.include_router(settings.router)
app.include_router(ws_router)


@app.get("/api/health")
async def health() -> dict[str, str]:
    """Health check for Electron backend manager."""
    return {"status": "ok", "service": "medusa-engine"}


def main() -> None:
    """Run the FastAPI server."""
    import uvicorn

    port = int(os.environ.get("MEDUSA_PORT", "17432"))
    data_dir = os.environ.get("MEDUSA_DATA_DIR", str(Path.home() / ".medusa"))
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    uvicorn.run(
        "medusa.engine.main:app",
        host="127.0.0.1",
        port=port,
        reload=os.environ.get("MEDUSA_DEV") == "1",
    )


if __name__ == "__main__":
    main()
