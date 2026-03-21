from __future__ import annotations
import hashlib
import json
import logging
from typing import AsyncIterator, Any, Type, TypeVar, Optional
from pydantic import BaseModel
from pentkit.core.config import AIConfig

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

from pentkit.core.ai_prompts import validate_ai_output

class AIEngine:
    """Central LLM integration layer for the pentkit framework."""
    
    def __init__(self, cfg: AIConfig):
        """
        Initialize the AI engine with configuration.
        """
        self.cfg = cfg
        self.token_usage = 0
        self._cache: dict[str, str] = {}
        # Configure litellm if possible
        try:
            import litellm
            litellm.drop_params = True
            # Optional: configure caching in litellm itself if available
        except (ImportError, ModuleNotFoundError):
            pass

    def _get_cache_key(self, system: str, user: str) -> str:
        """Generate a stable cache key from prompt content."""
        return hashlib.sha256((system + user).encode()).hexdigest()

    async def complete(
        self,
        system: str,
        user: str,
        schema: Type[T] | None = None,
        max_tokens: int = 1000,
    ) -> str | T:
        """
        Get a single completion from the LLM.
        """
        # Fallback if litellm is broken or not installed
        try:
            import litellm
        except (ImportError, ModuleNotFoundError):
            logger.error("litellm not found, returning empty response.")
            if schema:
                raise ValueError("AI engine unavailable")
            return "AI Engine Unavailable"

        cache_key = self._get_cache_key(system, user)
        if not schema and cache_key in self._cache:
            return self._cache[cache_key]

        # Truncate inputs if they exceed a reasonable limit (approx 6k tokens)
        # 1 token approx 4 characters
        max_chars = 24000
        if len(system) + len(user) > max_chars:
            logger.warning("Input too long, truncating before sending to AI.")
            user = user[:max_chars - len(system)]

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ]

        # Enforce structured output if schema is provided
        response_format = None
        if schema:
            response_format = {"type": "json_object"}

        retries = 3
        last_exception = None

        while retries > 0:
            try:
                response = await litellm.acompletion(
                    model=self.cfg.model,
                    messages=messages,
                    max_tokens=max_tokens or self.cfg.max_tokens,
                    temperature=self.cfg.temperature,
                    response_format=response_format
                )

                content = response.choices[0].message.content
                self.token_usage += response.usage.total_tokens

                if schema:
                    try:
                        # Use our validation logic
                        model_instance, confidence = validate_ai_output(content, schema)
                        if confidence < 0.1:
                            # Try again with a nudge
                            messages.append({"role": "assistant", "content": content})
                            messages.append({"role": "user", "content": "Return only the JSON, no prose."})
                            retries -= 1
                            continue
                        return model_instance
                    except (json.JSONDecodeError, ValueError) as e:
                        retries -= 1
                        last_exception = e
                        logger.warning(f"Failed to parse structured output, retrying... ({retries} left)")
                        continue
                else:
                    self._cache[cache_key] = content
                    return content

            except Exception as e:
                logger.error(f"AI completion failed: {e}")
                raise

        if schema:
            logger.error(f"Failed to get structured output after 3 retries: {last_exception}")
            # Return empty model as per spec fallback
            return schema.model_construct()
        
        return ""

    async def stream(self, system: str, user: str) -> AsyncIterator[str]:
        """
        Streaming completion for real-time output.
        """
        try:
            import litellm
        except (ImportError, ModuleNotFoundError):
            yield "AI Engine Unavailable"
            return

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ]

        response = await litellm.acompletion(
            model=self.cfg.model,
            messages=messages,
            stream=True,
            temperature=self.cfg.temperature
        )

        async for chunk in response:
            content = chunk.choices[0].delta.content
            if content:
                yield content

__all__ = ["AIEngine"]
