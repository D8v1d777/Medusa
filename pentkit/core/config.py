from __future__ import annotations
import yaml
from pathlib import Path
from typing import List, Literal, Optional
from functools import lru_cache
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

class EngagementConfig(BaseModel):
    name: str
    operator: str
    authorized: bool = False

class ScopeConfig(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)

class RatesConfig(BaseModel):
    web: float = 5.0
    network: float = 2.0
    redteam: float = 0.5

class AIConfig(BaseModel):
    provider: Literal["openai", "anthropic", "local"] = "openai"
    model: str = "gpt-4o"
    api_key_env: str = "OPENAI_API_KEY"
    max_tokens: int = 2000
    temperature: float = 0.2

class OutputConfig(BaseModel):
    evidence_dir: str = "~/.pentkit/evidence"
    log_dir: str = "~/.pentkit/logs"
    report_dir: str = "~/.pentkit/reports"

class Config(BaseSettings):
    engagement: EngagementConfig
    scope: ScopeConfig
    rates: RatesConfig = Field(default_factory=RatesConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    database_url: str = "sqlite:///pentkit.db"

    @classmethod
    def load(cls, config_path: str | Path = "config.yaml") -> Config:
        """Load config from YAML file."""
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
        return cls(**data)

@lru_cache()
def get_config(config_path: str = "config.yaml") -> Config:
    """Singleton getter for the configuration."""
    return Config.load(config_path)

__all__ = ["Config", "get_config", "EngagementConfig", "ScopeConfig", "RatesConfig", "AIConfig", "OutputConfig"]
