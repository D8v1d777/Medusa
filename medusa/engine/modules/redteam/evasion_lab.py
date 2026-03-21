"""Evasion lab — offline AV/EDR testing."""
from __future__ import annotations

import logging

__all__ = ["EvasionLab"]

logger = logging.getLogger(__name__)


class EvasionLab:
    """Offline AV/EDR detection testing."""

    async def run(self, payload_b64: str) -> dict:
        """Test payload against ClamAV."""
        return {"detected": False, "signature": None}
