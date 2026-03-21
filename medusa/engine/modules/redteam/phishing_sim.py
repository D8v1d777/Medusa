"""Phishing simulation — GoPhish integration."""
from __future__ import annotations

import logging

from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.core.session import Session

__all__ = ["PhishingSim"]

logger = logging.getLogger(__name__)


class PhishingSim:
    """GoPhish REST API integration."""

    def __init__(self, bucket: TokenBucket) -> None:
        self.bucket = bucket

    async def run(self, target: str, session: Session) -> None:
        """Run phishing simulation. Requires config."""
        pass
