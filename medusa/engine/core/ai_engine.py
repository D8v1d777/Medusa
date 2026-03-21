"""AI/LLM integration layer via litellm."""
from __future__ import annotations

import hashlib
import json
import logging
from typing import AsyncIterator, TypeVar

from pydantic import BaseModel

from medusa.engine.core.config import AIConfig

__all__ = ["AIEngine"]

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


def _validate_ai_output(raw: str, schema: type[BaseModel]) -> tuple[BaseModel, float]:
    """Parse and validate AI output. Return (model, confidence)."""
    content = raw
    for attempt in range(3):
        try:
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                content = content[start:end]
            elif "```" in content:
                start = content.find("```") + 3
                end = content.find("```", start)
                content = content[start:end]
            data = json.loads(content.strip())
            return schema.model_validate(data), 1.0
        except (json.JSONDecodeError, ValueError):
            continue
    return schema.model_construct(), 0.0


class AIEngine:
    """Central LLM integration layer."""

    def __init__(self, cfg: AIConfig) -> None:
        self.cfg = cfg
        self.token_usage = 0
        self._cache: dict[str, str] = {}

    def _get_cache_key(self, system: str, user: str) -> str:
        return hashlib.sha256((system + user).encode()).hexdigest()

    async def complete(
        self,
        system: str,
        user: str,
        schema: type[T] | None = None,
        max_tokens: int = 1000,
    ) -> str | T:
        """Single completion. If schema is set, return validated Pydantic model."""
        try:
            import litellm
        except ImportError:
            logger.error("litellm not found")
            if schema:
                return schema.model_construct()
            return "AI Engine Unavailable"

        cache_key = self._get_cache_key(system, user)
        if not schema and cache_key in self._cache:
            return self._cache[cache_key]

        max_chars = 24000
        if len(system) + len(user) > max_chars:
            user = user[: max_chars - len(system)]

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        response_format = {"type": "json_object"} if schema else None

        for _ in range(3):
            try:
                response = await litellm.acompletion(
                    model=self.cfg.model,
                    messages=messages,
                    max_tokens=max_tokens or self.cfg.max_tokens,
                    temperature=self.cfg.temperature,
                    response_format=response_format,
                )
                content = response.choices[0].message.content or ""
                self.token_usage += getattr(response.usage, "total_tokens", 0)

                if schema:
                    model_instance, _ = _validate_ai_output(content, schema)
                    return model_instance
                self._cache[cache_key] = content
                return content
            except Exception as e:
                logger.warning("AI completion failed: %s", e)
        if schema:
            return schema.model_construct()
        return ""

    async def stream(self, system: str, user: str) -> AsyncIterator[str]:
        """Streaming completion for real-time output."""
        try:
            import litellm
        except ImportError:
            yield "AI Engine Unavailable"
            return

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        response = await litellm.acompletion(
            model=self.cfg.model,
            messages=messages,
            stream=True,
            temperature=self.cfg.temperature,
        )
        async for chunk in response:
            content = chunk.choices[0].delta.content
            if content:
                yield content
