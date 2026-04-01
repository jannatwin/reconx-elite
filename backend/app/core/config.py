from functools import cached_property

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ReconX Elite API"

    database_url: str = "postgresql+psycopg2://reconx:reconx@postgres:5432/reconx"
    redis_url: str = "redis://redis:6379/0"

    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 120
    refresh_token_expire_minutes: int = 10080

    cors_allowed_origins: str = "http://localhost:5173,http://localhost:3000"

    scan_allowed_schemes: str = "http,https"
    nuclei_templates: str = ""
    scan_throttle_seconds: int = 20
    js_fetch_timeout_seconds: int = 6
    js_fetch_max_assets: int = 12
    js_fetch_max_bytes: int = 200000
    scan_nuclei_target_cap: int = 300
    scan_header_probe_cap: int = 50

    register_rate_limit: str = "10/minute"
    login_rate_limit: str = "20/minute"
    refresh_rate_limit: str = "30/minute"
    read_rate_limit: str = "120/minute"
    write_rate_limit: str = "60/minute"
    scan_rate_limit: str = "12/minute"
    report_rate_limit: str = "30/minute"

    scheduled_scan_poll_minutes: int = 10

    takeover_cname_indicators: str = (
        "amazonaws.com,azurewebsites.net,herokudns.com,github.io,cloudfront.net,"
        "trafficmanager.net,fastly.net,readme.io,pantheonsite.io"
    )

    @cached_property
    def cors_allowed_origins_list(self) -> list[str]:
        return [value.strip() for value in self.cors_allowed_origins.split(",") if value.strip()]

    @cached_property
    def allowed_schemes(self) -> tuple[str, ...]:
        return tuple(value.strip().lower() for value in self.scan_allowed_schemes.split(",") if value.strip())

    @cached_property
    def takeover_indicators(self) -> tuple[str, ...]:
        return tuple(value.strip().lower() for value in self.takeover_cname_indicators.split(",") if value.strip())


settings = Settings()
