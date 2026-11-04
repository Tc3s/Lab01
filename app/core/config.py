"""
Core Application Configuration
Loads environment variables using Pydantic Settings v2.
"""

from functools import lru_cache
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Project Information
    PROJECT_NAME: str = "Secure E-Commerce Admin Portal"
    APP_ENV: str = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Cryptography & Secrets
    SECRET_KEY: str = Field(
        default="e-commerce-lab-secure-secret-key-min-32-chars-long!",
        description="Master secret key for application cryptographic operations"
    )

    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./data/ecommerce.db",
        description="Database connection URL"
    )

    # Redis Configuration
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    REDIS_MAX_CONNECTIONS: int = 50
    REDIS_SOCKET_TIMEOUT: float = 5.0
    REDIS_SOCKET_CONNECT_TIMEOUT: float = 5.0
    REDIS_HEALTH_CHECK_INTERVAL: int = 30

    # Session Timeouts (Seconds)
    SESSION_COOKIE_NAME: str = "session_id"
    SESSION_IDLE_TIMEOUT_SECONDS: int = 900          # 15 minutes
    SESSION_ABSOLUTE_TIMEOUT_SECONDS: int = 28800     # 8 hours
    PRE_MFA_SESSION_TIMEOUT_SECONDS: int = 300       # 5 minutes for pre-MFA temp session

    # Anti-Replay Configuration
    OTP_REPLAY_TTL_SECONDS: int = 90                 # 90 seconds (3 * 30s TOTP steps)

    # Cookie Security Flags
    COOKIE_SECURE: bool = False                      # Set to True for production HTTPS
    COOKIE_HTTPONLY: bool = True                     # Block JavaScript access
    COOKIE_SAMESITE: str = "lax"                     # Strict or Lax CSRF mitigation
    COOKIE_DOMAIN: Optional[str] = None
    COOKIE_PATH: str = "/"

    # Audit & Compliance
    AUDIT_LOG_FILE: str = "logs/audit.log"
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton instance."""
    return Settings()


settings = get_settings()
