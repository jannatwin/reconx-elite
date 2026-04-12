import logging
from pathlib import Path
from functools import cached_property

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ENV_FILES = (str(REPO_ROOT / ".env"), ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=DEFAULT_ENV_FILES,
        env_file_encoding="utf-8",
        extra="ignore",
    )

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
    read_rate_limit: str = "60/minute"
    write_rate_limit: str = "20/minute"
    ai_rate_limit: str = "10/minute"
    auth_rate_limit: str = "10/minute"
    scan_rate_limit: str = "12/minute"
    report_rate_limit: str = "30/minute"
    ticketing_rate_limit: str = "20/minute"

    scheduled_scan_poll_minutes: int = 10

    # Ticketing integration settings
    jira_url: str = ""
    jira_username: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""
    jira_issue_type: str = "Bug"

    github_token: str = ""
    github_repository: str = ""
    github_assignee: str = ""

    gitlab_url: str = "https://gitlab.com"
    gitlab_token: str = ""
    gitlab_project_id: str = ""
    gitlab_assignee_id: str = ""

    takeover_cname_indicators: str = (
        "amazonaws.com,azurewebsites.net,herokudns.com,github.io,cloudfront.net,"
        "trafficmanager.net,fastly.net,readme.io,pantheonsite.io"
    )

    gemini_api_key: str = ""
    openrouter_key: str = ""
    openrouter_api_key_secondary: str = ""
    openrouter_api_key_tertiary: str = ""
    ai_provider: str = "gemini"  # legacy setting, use ai_scan_provider instead
    ai_model: str = "gemini-1.5-flash"  # legacy setting, use ai_scan_model instead

    # Task-specific AI settings
    ai_scan_provider: str = "gemini"  # Low-cost, high-speed (Gemini Flash)
    ai_scan_model: str = "gemini-1.5-flash"
    
    ai_analyze_provider: str = "gemini"  # Balanced reasoning (GPT-4o mini, Llama 3.1 70B)
    ai_analyze_model: str = "gemini-1.5-flash" # Default to flash if not set
    
    ai_report_provider: str = "gemini"  # High reasoning, expert writing (GPT-4o, Gemini Pro, Claude 3.5 Sonnet)
    ai_report_model: str = "gemini-1.5-pro"
    
    # Notification webhooks
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    
    # Gemini API resilience and AI input sizing
    gemini_max_retries: int = 3
    gemini_retry_base_seconds: float = 15.0
    gemini_retry_max_sleep_seconds: float = 90.0
    ai_max_input_chars: int = 12000
    callback_url: str = "http://localhost:8000"

    # Advanced Reconnaissance Settings
    advanced_recon_enabled: bool = True
    default_scan_mode: str = "balanced"  # aggressive, balanced, stealth
    max_parameter_discovery_endpoints: int = 50
    max_content_fuzzing_requests: int = 100
    max_adaptive_analysis_endpoints: int = 20
    parameter_discovery_timeout_seconds: int = 300
    content_fuzzing_timeout_seconds: int = 600
    adaptive_analysis_timeout_seconds: int = 300

    # Modular pipeline / passive DNS
    scan_crtsh_timeout_seconds: float = 90.0
    scan_crtsh_max_names: int = 5000
    scan_github_subdomains_timeout_seconds: int = 180
    scan_github_subdomains_max_names: int = 2000

    # Wordlists (worker-full mounts Seclists here)
    seclists_base_path: str = ""

    # Tier B — active discovery caps
    scan_active_dns_max_labels: int = 500
    scan_ffuf_timeout_seconds: int = 300
    scan_wayback_max_urls: int = 5000
    scan_katana_timeout_seconds: int = 600
    scan_katana_max_urls: int = 2000

    # Tier B — port / screenshots / WAF
    scan_nmap_timeout_seconds: int = 600
    scan_nmap_max_hosts: int = 50
    scan_gowitness_timeout_seconds: int = 900
    scan_wafw00f_timeout_seconds: int = 120

    # Tier C — aggressive (requires enable_aggressive_scanning)
    enable_aggressive_scanning: bool = False
    scan_aggressive_timeout_seconds: int = 900
    scan_sqlmap_max_urls: int = 3
    scan_dalfox_max_urls: int = 3
    scan_masscan_max_hosts: int = 5
    scan_masscan_rate: int = 500

    # Nuclei OOB (optional self-hosted interactsh)
    interactsh_server_url: str = ""

    # Database connection pool tuning
    db_pool_size: int = 20
    db_max_overflow: int = 30
    db_pool_recycle: int = 3600
    db_pool_timeout: int = 30

    # HTTPS / proxy
    https_behind_proxy: bool = False

    # Redis cache
    redis_cache_ttl: int = 60

    # Backup
    backup_dest_path: str = "/backups"
    backup_retention_days: int = 7

    # Metrics
    metrics_enabled: bool = True

    @cached_property
    def cors_allowed_origins_list(self) -> list[str]:
        return [value.strip() for value in self.cors_allowed_origins.split(",") if value.strip()]

    @cached_property
    def allowed_schemes(self) -> tuple[str, ...]:
        return tuple(value.strip().lower() for value in self.scan_allowed_schemes.split(",") if value.strip())

    @cached_property
    def takeover_indicators(self) -> tuple[str, ...]:
        return tuple(value.strip().lower() for value in self.takeover_cname_indicators.split(",") if value.strip())

    @property
    def openrouter_api_key(self) -> str:
        return self.openrouter_key

    @property
    def backend_callback_url(self) -> str:
        return self.callback_url

    @property
    def runtime_validation_errors(self) -> tuple[str, ...]:
        errors: list[str] = []
        if self.jwt_secret_key == "change-me-in-production":
            errors.append("JWT_SECRET_KEY must be changed from the default value")
        return tuple(errors)

    def validate_runtime_or_raise(self) -> None:
        if self.runtime_validation_errors:
            raise RuntimeError("; ".join(self.runtime_validation_errors))


settings = Settings()

_logger = logging.getLogger(__name__)
for message in settings.runtime_validation_errors:
    _logger.warning("Runtime configuration warning: %s", message)
