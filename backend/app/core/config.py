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
