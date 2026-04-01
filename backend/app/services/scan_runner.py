from app.core.config import settings
from app.services.scan_parser import (
    parse_gau_output,
    parse_httpx_enrich_output,
    parse_httpx_headers_output,
    parse_httpx_live_output,
    parse_nuclei_output,
    parse_subfinder_output,
)
from app.services.tool_executor import ToolExecutionResult, execute_with_retry


def run_subfinder(domain: str) -> tuple[list[str], ToolExecutionResult]:
    result = execute_with_retry("subfinder", ["subfinder", "-silent", "-d", domain], timeout_seconds=120)
    if result.status != "success":
        return [], result
    return parse_subfinder_output(result.stdout), result


def run_httpx(hosts: list[str]) -> tuple[list[str], ToolExecutionResult | None]:
    if not hosts:
        return [], None
    result = execute_with_retry(
        "httpx",
        ["httpx", "-silent", "-json", "-status-code", "-follow-redirects"],
        stdin_payload="\n".join(hosts) + "\n",
        timeout_seconds=180,
    )
    if result.status != "success":
        return [], result
    return parse_httpx_live_output(result.stdout), result


def run_httpx_enrich(hosts: list[str]) -> tuple[dict[str, dict], ToolExecutionResult | None]:
    if not hosts:
        return {}, None
    result = execute_with_retry(
        "httpx",
        ["httpx", "-silent", "-json", "-ip", "-tech-detect", "-cdn", "-cname", "-title", "-status-code"],
        stdin_payload="\n".join(hosts) + "\n",
        timeout_seconds=180,
    )
    if result.status != "success":
        return {}, result
    return parse_httpx_enrich_output(result.stdout), result


def run_gau(domain: str) -> tuple[list[str], ToolExecutionResult]:
    result = execute_with_retry("gau", ["gau", "--subs", domain], timeout_seconds=180)
    if result.status != "success":
        return [], result
    return parse_gau_output(result.stdout), result


def run_nuclei(targets: list[str], config: dict | None = None) -> tuple[list[dict], ToolExecutionResult | None]:
    if not targets:
        return [], None
    command = ["nuclei", "-silent", "-jsonl"]
    selected_templates = (config or {}).get("selected_templates") or []
    severity_filter = (config or {}).get("severity_filter") or []
    if selected_templates:
        command.extend(["-tags", ",".join(selected_templates)])
    if severity_filter:
        command.extend(["-severity", ",".join(severity_filter)])
    if settings.nuclei_templates:
        command.extend(["-t", settings.nuclei_templates])
    result = execute_with_retry(
        "nuclei",
        command,
        stdin_payload="\n".join(targets) + "\n",
        timeout_seconds=300,
    )
    if result.status != "success":
        return [], result
    return parse_nuclei_output(result.stdout), result


def check_headers(urls: list[str]) -> tuple[list[dict], ToolExecutionResult | None]:
    if not urls:
        return [], None
    scheme_allow = tuple(f"{scheme}://" for scheme in settings.allowed_schemes)
    scoped_urls = [u for u in urls if u.startswith(scheme_allow)]
    if not scoped_urls:
        return [], None
    result = execute_with_retry(
        "httpx-headers",
        ["httpx", "-silent", "-json", "-H", "User-Agent: ReconX"],
        stdin_payload="\n".join(scoped_urls) + "\n",
        timeout_seconds=180,
    )
    if result.status != "success":
        return [], result
    return parse_httpx_headers_output(result.stdout), result
