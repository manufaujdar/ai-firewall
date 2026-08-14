from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AI_FIREWALL_",
        env_file=".env",
        extra="forbid",
    )

    policy_path: Path = Path("config/policy.yaml")
    models_path: Path = Path("config/models.yaml")
    audit_path: Path = Path("data/audit.jsonl")
    database_path: Path = Path("data/privacy.db")
    fail_closed: Literal[True] = True
    api_key: str | None = Field(default=None, min_length=32)
    # Proxy transport is intentionally unavailable until DNS pinning and local
    # provider credential adapters are implemented and verified.
    proxy_enabled: Literal[False] = False
    trusted_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    request_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    max_payload_bytes: int = Field(default=1_000_000, gt=0, le=10_000_000)


settings = Settings()
