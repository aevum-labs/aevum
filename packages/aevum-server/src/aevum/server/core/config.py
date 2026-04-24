"""
Server configuration via environment variables.
All settings have safe defaults for development.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEVUM_", case_sensitive=False)

    # Network
    host: str = "0.0.0.0"
    port: int = 8000

    # Auth
    api_key: str = "dev-insecure-key-change-in-production"

    # Policy (optional — permissive stub if not set)
    opa_url: str = ""

    # Rate limiting (headers always present; enforcement is operator responsibility)
    rate_limit_per_minute: int = 1000

    # OTel
    otel_enabled: bool = False
    otel_service_name: str = "aevum-server"
