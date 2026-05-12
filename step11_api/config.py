"""
config.py — Application settings for the SBOM POC Tool API.

All values are loaded from environment variables (or .env file) with
safe defaults. No secrets are hardcoded.

Session: SBOM-20260409-sb01
Generated: Step 11 — FastAPI API Generation
"""

from __future__ import annotations

from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application-level configuration.

    Override any setting via environment variables or a .env file placed
    next to the application entry-point (main.py).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------
    APP_NAME: str = "SBOM POC Tool API"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = False
    VERSION: str = "0.1.0"

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
    ]

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    LOG_LEVEL: str = "INFO"

    # ------------------------------------------------------------------
    # NVD Cache
    # ------------------------------------------------------------------
    # Set to a filesystem path (e.g. "/data/nvd_cache.db") to persist the
    # NVD cache across application restarts. Defaults to ":memory:" (POC mode).
    NVD_CACHE_DB_PATH: str = ":memory:"

    # ------------------------------------------------------------------
    # Git clone workspace
    # ------------------------------------------------------------------
    # Directory under which public-repo clones are stored (one subdir per repo).
    # Defaults to <session_root>/clones; override with SBOM_CLONES_DIR.
    SBOM_CLONES_DIR: str = ""
    # Hard timeout for `git clone --depth=1`, in seconds.
    SBOM_CLONE_TIMEOUT_SECONDS: int = 120

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}; got {v!r}")
        return upper


# Module-level singleton consumed by all routers and dependencies.
settings = Settings()
