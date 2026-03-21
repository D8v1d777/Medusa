"""AI lure — LLM-generated spear-phish content."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


__all__ = ["generate_lure", "Lure"]


@dataclass
class Lure:
    """Generated phishing lure."""

    subject: str
    body_html: str
    sender_name: str
    ioc_risk: str


async def generate_lure(
    target_name: str,
    target_role: str,
    organisation: str,
    pretext: str,
    tone: Literal["urgent", "routine", "friendly"] = "routine",
) -> Lure:
    """Generate spear-phish content. For awareness testing only."""
    return Lure(
        subject=f"Action required: {pretext}",
        body_html=f"<p>Dear {target_name},</p><p>Please review the attached.</p>",
        sender_name="IT Security",
        ioc_risk="Standard corporate template",
    )
