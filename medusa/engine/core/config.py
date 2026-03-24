"""Configuration — Pydantic v2 schema and YAML loader."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

__all__ = [
    "Config",
    "get_config",
    "EngagementConfig",
    "ScopeConfig",
    "RatesConfig",
    "AIConfig",
    "OutputConfig",
]


class EngagementConfig(BaseModel):
    """Engagement configuration."""

    name: str = "Default Engagement"
    operator: str = "Analyst"
    authorized: bool = False


class ScopeConfig(BaseModel):
    """Scope definition for the engagement."""

    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)


class RatesConfig(BaseModel):
    """Rate limits per module type."""

    web: float = 5.0
    network: float = 2.0
    redteam: float = 0.5


class AIConfig(BaseModel):
    """AI/LLM provider configuration."""

    provider: Literal["openai", "anthropic", "local", "groq"] = "openai"
    model: str = "llama-3.3-70b-versatile"
    api_key_env: str = "GROQ_API_KEY"
    api_key: str | None = None
    max_tokens: int = 2000
    temperature: float = 0.2


class OutputConfig(BaseModel):
    """Output directories."""

    evidence_dir: str = "~/.medusa/evidence"
    log_dir: str = "~/.medusa/logs"
    report_dir: str = "~/.medusa/reports"


class Config(BaseModel):
    """Root configuration model."""

    engagement: EngagementConfig = Field(default_factory=EngagementConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rates: RatesConfig = Field(default_factory=RatesConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    database_url: str = "sqlite:///medusa.db"

    @classmethod
    def load(cls, config_path: str | Path = "config.yaml") -> Config:
        """Load config from YAML file. Uses defaults if file not found."""
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return cls(**data)
        return cls()


@lru_cache(maxsize=1)
def get_config(config_path: str = "config_medusa.yaml") -> Config:
    """Singleton getter for the configuration."""
    return Config.load(config_path)
