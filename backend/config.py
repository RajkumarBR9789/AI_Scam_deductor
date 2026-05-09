"""
Application configuration using pydantic-settings.
Loads all settings from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Central configuration class for ScamShield backend."""

    DATABASE_URL: str = Field(..., description="PostgreSQL connection string")
    SECRET_KEY: str = Field(..., min_length=32, description="JWT signing secret (min 32 chars)")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REFRESH_TOKEN_REMEMBER_DAYS: int = 30
    APP_NAME: str = "ScamShield"
    DEBUG: bool = False

    FASTAPI_HOST: str = "0.0.0.0"
    FASTAPI_PORT: int = 8000

    # Refresh-token cookie settings
    AUTH_COOKIE_NAME: str = "refresh_token"
    AUTH_COOKIE_PATH: str = "/"
    AUTH_COOKIE_DOMAIN: str = ""
    AUTH_COOKIE_SECURE: bool = False
    AUTH_COOKIE_SAMESITE: str = "lax"

    # Email / SMTP settings for OTP delivery
    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 587
    EMAIL_USER: str = ""
    EMAIL_PASSWORD: str = ""
    EMAIL_FROM: str = ""
    OTP_EXPIRE_MINUTES: int = 5
    RESET_TOKEN_EXPIRE_MINUTES: int = 5

    # External API keys for scan features
    SERPAPI_KEY: str = ""
    GROQ_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_KEY: str = ""

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    SCAN_CACHE_TTL_SECONDS: int = 3600

    # Sentry
    SENTRY_DSN: str = ""
    SENTRY_TRACES_SAMPLE_RATE: float = 0.1

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" or "console"

    # Scan limits
    FREE_DAILY_SCAN_LIMIT: int = 5

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
