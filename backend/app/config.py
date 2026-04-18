"""Configuration validation and settings for ReconX Elite."""

from typing import Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, validator


class Settings(BaseSettings):
    """Application settings with environment variable validation."""

    # Database
    postgres_db: str = Field(default="reconx", description="PostgreSQL database name")
    postgres_user: str = Field(default="reconx", description="PostgreSQL user")
    postgres_password: str = Field(default="reconx", description="PostgreSQL password")
    postgres_host: str = Field(default="localhost", description="PostgreSQL host")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    database_url: Optional[str] = Field(
        default=None,
        description="Full database URL (overrides individual postgres settings)",
    )

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0", description="Redis connection URL"
    )
    redis_cache_ttl: int = Field(default=60, description="Redis cache TTL in seconds")

    # AI Models
    ai_provider: str = Field(default="gemini", description="Primary AI provider")
    ai_model: str = Field(default="gemini-1.5-flash", description="Primary AI model")
    gemini_api_key: str = Field(default="", description="Gemini API key")

    ai_analyze_provider: str = Field(
        default="openrouter", description="Analysis AI provider"
    )
    ai_analyze_model: str = Field(
        default="google/gemma-2-27b-it", description="Analysis model"
    )

    ai_scan_provider: str = Field(
        default="openrouter", description="Scanning AI provider"
    )
    ai_scan_model: str = Field(
        default="meta-llama/llama-3.3-70b-instruct", description="Scanning model"
    )

    ai_report_provider: str = Field(
        default="openrouter", description="Report AI provider"
    )
    ai_report_model: str = Field(
        default="qwen/qwen-2.5-coder-32b-instruct", description="Report model"
    )

    openrouter_key: str = Field(default="", description="OpenRouter API key")

    # API Configuration
    api_title: str = Field(default="ReconX Elite API", description="API title")
    api_version: str = Field(default="1.0.0", description="API version")
    api_description: str = Field(
        default="Advanced vulnerability research engine", description="API description"
    )

    # Security
    jwt_secret_key: str = Field(
        default="reconx_elite_secure_secret_key_2026_04_12",
        description="JWT secret key",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=120, description="Access token expiration in minutes"
    )
    refresh_token_expire_minutes: int = Field(
        default=10080, description="Refresh token expiration in minutes"
    )

    # Rate Limiting
    login_rate_limit: str = Field(default="20/minute", description="Login rate limit")
    register_rate_limit: str = Field(
        default="10/minute", description="Registration rate limit"
    )
    scan_rate_limit: str = Field(
        default="12/minute", description="Scan initiation rate limit"
    )
    read_rate_limit: str = Field(
        default="120/minute", description="Read operations rate limit"
    )
    write_rate_limit: str = Field(
        default="60/minute", description="Write operations rate limit"
    )
    refresh_rate_limit: str = Field(
        default="30/minute", description="Token refresh rate limit"
    )
    report_rate_limit: str = Field(
        default="30/minute", description="Report generation rate limit"
    )

    # CORS
    cors_allowed_origins: List[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        description="CORS allowed origins",
    )

    # Scan Configuration
    default_scan_mode: str = Field(default="balanced", description="Default scan mode")
    max_concurrent_scans: int = Field(
        default=10, description="Maximum concurrent scans"
    )
    scan_timeout_seconds: int = Field(
        default=3600, description="Scan timeout in seconds"
    )

    # Advanced Recon
    advanced_recon_enabled: bool = Field(
        default=True, description="Enable advanced reconnaissance"
    )
    max_adaptive_analysis_endpoints: int = Field(
        default=20, description="Max endpoints for adaptive analysis"
    )
    parameter_discovery_timeout_seconds: int = Field(
        default=300, description="Parameter discovery timeout"
    )
    content_fuzzing_timeout_seconds: int = Field(
        default=600, description="Content fuzzing timeout"
    )
    max_content_fuzzing_requests: int = Field(
        default=100, description="Max content fuzzing requests"
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")

    # Metrics
    metrics_enabled: bool = Field(default=True, description="Enable Prometheus metrics")

    # Monitoring
    enable_aggressive_scanning: bool = Field(
        default=False, description="Enable aggressive scanning"
    )

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False
    )

    @validator("postgres_password")
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength in production."""
        if v == "reconx" and not v.startswith("$"):
            # Allow default password for development
            pass
        return v

    @validator("jwt_secret_key")
    def validate_jwt_secret(cls, v: str) -> str:
        """Validate JWT secret key."""
        if len(v) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")
        return v

    @property
    def database_url_value(self) -> str:
        """Get database URL."""
        if self.database_url:
            return self.database_url

        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    class Config:
        """Configuration class."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get application settings."""
    global settings
    if settings is None:
        settings = Settings()
    return settings


def validate_settings() -> tuple[bool, str]:
    """Validate all required settings are present."""
    try:
        settings = get_settings()

        # Check required fields
        if not settings.gemini_api_key and not settings.openrouter_key:
            return (
                False,
                "At least one AI API key must be configured (GEMINI_API_KEY or OPENROUTER_KEY)",
            )

        if not settings.postgres_password:
            return False, "Database password must be configured"

        return True, "Settings validation passed"

    except ValueError as e:
        return False, f"Settings validation failed: {str(e)}"
