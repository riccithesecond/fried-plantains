"""
config.py — Application configuration loaded from environment variables.

This is the only place environment variables are read. Every other module imports
`settings` from here. Pydantic Settings validates all fields at startup — missing
or malformed required vars raise a clear ValidationError before any server traffic
is handled.
"""

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Security — required, no defaults
    SECRET_KEY: str
    ADMIN_USERNAME: str
    ADMIN_PASSWORD_HASH: str

    # Token lifetimes
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Query engine
    QUERY_TIMEOUT_SECONDS: float = 30.0
    MAX_UPLOAD_SIZE_MB: int = 500

    # Storage
    STORAGE_ROOT: str = "./storage"

    # Server
    CORS_ORIGIN: str = "http://localhost:5173"
    LOG_LEVEL: str = "INFO"

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_min_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("CORS_ORIGIN")
    @classmethod
    def cors_no_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @property
    def max_upload_size_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024


# Module-level singleton — import `settings` everywhere, never os.getenv() directly
settings = Settings()
