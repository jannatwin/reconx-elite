"""Resolve Celery scan stage order from scan_config_json."""

from __future__ import annotations

from app.core.config import settings
from app.schemas.scan_modules import ScanModulesConfig, parse_modules_from_config

# Stage ids must match task registry keys in scan_tasks.STAGE_REGISTRY
STANDARD_PIPELINE = ("subfinder", "httpx", "gau", "nuclei")


def resolve_pipeline_stages(scan_config: dict | None) -> list[str]:
    cfg = scan_config or {}
    modules = parse_modules_from_config(cfg)
    profile = cfg.get("profile")

    if profile == "standard" or not cfg.get("modules"):
        return list(STANDARD_PIPELINE)

    return _stages_from_modules(modules)


def _stages_from_modules(m: ScanModulesConfig) -> list[str]:
    stages: list[str] = []
    if m.passive_dns.crtsh_enabled or m.passive_dns.github_subdomains_enabled:
        stages.append("passive_dns")
    stages.append("subfinder")
    if m.active_dns.enabled:
        stages.append("active_dns")
    stages.append("httpx")
    if m.port_scan.enabled:
        stages.append("port_scan")
    if m.screenshots.enabled:
        stages.append("screenshots")
    if m.waf_fingerprint.enabled:
        stages.append("waf_fingerprint")
    stages.append("gau")
    if m.url_sources.wayback_enabled:
        stages.append("waybackurls")
    if m.url_sources.katana_enabled:
        stages.append("katana")
    if m.content_discovery.ffuf_dir_enabled:
        stages.append("ffuf_dir")
    if m.aggressive.enabled and settings.enable_aggressive_scanning:
        stages.append("aggressive")
    stages.append("nuclei")
    return stages


def pipeline_stage_total(scan_config: dict | None) -> int:
    return len(resolve_pipeline_stages(scan_config))


def stage_index_and_total(scan_metadata: dict | None, stage_name: str) -> tuple[int, int]:
    stages = (scan_metadata or {}).get("pipeline_stages") or list(STANDARD_PIPELINE)
    total = len(stages)
    try:
        idx = stages.index(stage_name) + 1
    except ValueError:
        idx = 1
    return idx, total
