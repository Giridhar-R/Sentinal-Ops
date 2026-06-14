"""
SentinelOps — Configuration Module
Loads and validates all settings from environment variables / .env file.
"""

from __future__ import annotations

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field


# Resolve project root (two levels up from this file)
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class SplunkSettings(BaseSettings):
    """Splunk MCP Server connection settings."""

    host: str = Field(default="https://localhost", alias="SPLUNK_HOST")
    port: int = Field(default=8089, alias="SPLUNK_PORT")
    token: str = Field(default="changeme", alias="SPLUNK_TOKEN")
    mcp_mode: str = Field(default="sse", alias="SPLUNK_MCP_MODE")
    index: str = Field(default="botsv3", alias="SPLUNK_INDEX")
    verify_ssl: bool = Field(default=False, alias="SPLUNK_VERIFY_SSL")
    ai_assistant_enabled: bool = Field(
        default=False, alias="SPLUNK_AI_ASSISTANT_ENABLED"
    )

    @property
    def base_url(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def mcp_sse_url(self) -> str:
        return f"{self.base_url}/services/mcp/sse"


class LLMSettings(BaseSettings):
    """LLM provider configuration."""

    provider: str = Field(default="openai", alias="LLM_PROVIDER")
    api_key: str = Field(default="changeme", alias="LLM_API_KEY")
    model: str = Field(default="gpt-4o", alias="LLM_MODEL")
    temperature: float = Field(default=0.1, alias="LLM_TEMPERATURE")
    max_tokens: int = Field(default=4096, alias="LLM_MAX_TOKENS")


class SOARSettings(BaseSettings):
    """Splunk SOAR integration (optional)."""

    enabled: bool = Field(default=False, alias="SOAR_ENABLED")
    host: str = Field(default="https://localhost", alias="SOAR_HOST")
    token: str = Field(default="changeme", alias="SOAR_TOKEN")


class AppSettings(BaseSettings):
    """Top-level application settings."""

    demo_mode: bool = Field(default=True, alias="DEMO_MODE")
    host: str = Field(default="0.0.0.0", alias="FASTAPI_HOST")
    port: int = Field(default=8000, alias="FASTAPI_PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Sub-settings
    splunk: SplunkSettings = SplunkSettings()
    llm: LLMSettings = LLMSettings()
    soar: SOARSettings = SOARSettings()

    model_config = {
        "env_file": str(PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


def get_settings() -> AppSettings:
    """Load and return validated application settings."""
    return AppSettings()
