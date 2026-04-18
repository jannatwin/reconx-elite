"""Optional scan modules (extended pipeline). Omitted fields use safe defaults."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class PassiveDnsModule(BaseModel):
    crtsh_enabled: bool = False
    github_subdomains_enabled: bool = False


class UrlSourcesModule(BaseModel):
    wayback_enabled: bool = False
    katana_enabled: bool = False
    katana_depth: int = Field(default=3, ge=1, le=10)


class ActiveDnsModule(BaseModel):
    enabled: bool = False
    wordlist_path: str = ""
    max_fuzz_labels: int = Field(default=200, ge=1, le=50_000)


class ContentDiscoveryModule(BaseModel):
    ffuf_dir_enabled: bool = False
    base_url: str = ""
    wordlist_path: str = ""
    max_matches: int = Field(default=200, ge=1, le=10_000)


class PortScanModule(BaseModel):
    enabled: bool = False
    ports: str = "80,443,8080,8443,3000,8000"


class ScreenshotsModule(BaseModel):
    enabled: bool = False
    delay_seconds: int = Field(default=2, ge=0, le=30)


class WafFingerprintModule(BaseModel):
    enabled: bool = False
    sample_size: int = Field(default=10, ge=1, le=100)


class NucleiExtrasModule(BaseModel):
    include_takeover: bool = False
    include_cors: bool = False
    include_ssrf: bool = False
    include_missing_headers: bool = False


class AggressiveModule(BaseModel):
    enabled: bool = False
    run_sqlmap: bool = False
    run_dalfox: bool = False
    run_masscan: bool = False


class ScanModulesConfig(BaseModel):
    passive_dns: PassiveDnsModule = Field(default_factory=PassiveDnsModule)
    url_sources: UrlSourcesModule = Field(default_factory=UrlSourcesModule)
    active_dns: ActiveDnsModule = Field(default_factory=ActiveDnsModule)
    content_discovery: ContentDiscoveryModule = Field(
        default_factory=ContentDiscoveryModule
    )
    port_scan: PortScanModule = Field(default_factory=PortScanModule)
    screenshots: ScreenshotsModule = Field(default_factory=ScreenshotsModule)
    waf_fingerprint: WafFingerprintModule = Field(default_factory=WafFingerprintModule)
    nuclei_extras: NucleiExtrasModule = Field(default_factory=NucleiExtrasModule)
    aggressive: AggressiveModule = Field(default_factory=AggressiveModule)


ScanProfile = Literal["standard", "extended"]


def parse_modules_from_config(cfg: dict | None) -> ScanModulesConfig:
    if not cfg:
        return ScanModulesConfig()
    raw = cfg.get("modules")
    if not raw or not isinstance(raw, dict):
        return ScanModulesConfig()
    return ScanModulesConfig.model_validate(raw)


def modules_to_dict(modules: ScanModulesConfig) -> dict[str, Any]:
    return modules.model_dump()
