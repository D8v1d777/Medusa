"""Report engine — HTML/PDF report generation."""
from __future__ import annotations

from medusa.engine.core.session import Session

__all__ = ["ReportEngine"]


class ReportEngine:
    """Generates executive and technical reports."""

    def __init__(self, session: Session) -> None:
        self.session = session

    async def render_executive(self) -> str:
        """Render executive summary HTML."""
        from medusa.engine.modules.ai.report_writer import write_executive_summary
        body = await write_executive_summary(self.session)
        return f"<html><body><h1>Executive Summary</h1><p>{body}</p></body></html>"
