import json
import os
import shutil
import tempfile

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


def run_gau(targets: str | list[str]) -> tuple[list[str], ToolExecutionResult]:
    if isinstance(targets, list):
        stdin_payload = "\n".join(targets) + "\n"
        result = execute_with_retry(
            "gau",
            ["gau", "--subs"],
            stdin_payload=stdin_payload,
            timeout_seconds=180,
        )
    else:
        result = execute_with_retry("gau", ["gau", "--subs", targets], timeout_seconds=180)
    if result.status != "success":
        return [], result
    return parse_gau_output(result.stdout), result


def run_nuclei(targets: list[str], config: dict | None = None) -> tuple[list[dict], ToolExecutionResult | None]:
    if not targets:
        return [], None
    command = ["nuclei", "-silent", "-jsonl"]
    selected_templates = list((config or {}).get("selected_templates") or [])
    severity_filter = (config or {}).get("severity_filter") or []
    nex = (config or {}).get("nuclei_extras") or {}
    extra_tags: list[str] = []
    if nex.get("include_takeover"):
        extra_tags.append("takeover")
    if nex.get("include_cors"):
        extra_tags.append("cors")
    if nex.get("include_ssrf"):
        extra_tags.append("ssrf")
    if nex.get("include_missing_headers"):
        extra_tags.append("misconfig")
    tag_union = selected_templates + [t for t in extra_tags if t not in selected_templates]
    if tag_union:
        command.extend(["-tags", ",".join(tag_union)])
    if severity_filter:
        command.extend(["-severity", ",".join(severity_filter)])
    if settings.nuclei_templates:
        command.extend(["-t", settings.nuclei_templates])
    if settings.interactsh_server_url:
        command.extend(["-interactsh-url", settings.interactsh_server_url])
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


def _which_or_none(name: str) -> str | None:
    return shutil.which(name)


def run_waybackurls(domain: str) -> tuple[list[str], ToolExecutionResult | None]:
    wb = _which_or_none("waybackurls")
    if not wb:
        return [], None
    result = execute_with_retry(
        "waybackurls",
        [wb, domain],
        timeout_seconds=settings.scan_ffuf_timeout_seconds,
    )
    if result.status != "success":
        return [], result
    urls = [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("http")]
    return urls[: settings.scan_wayback_max_urls], result


def run_katana(seeds: list[str], depth: int) -> tuple[list[str], ToolExecutionResult | None]:
    kat = _which_or_none("katana")
    if not kat or not seeds:
        return [], None
    out_lines: list[str] = []
    last_res: ToolExecutionResult | None = None
    for seed in seeds[:20]:
        result = execute_with_retry(
            "katana",
            [kat, "-u", seed, "-silent", "-d", str(depth), "-jc"],
            timeout_seconds=settings.scan_katana_timeout_seconds,
        )
        last_res = result
        if result.status != "success":
            continue
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("http"):
                out_lines.append(line)
            if len(out_lines) >= settings.scan_katana_max_urls:
                break
        if len(out_lines) >= settings.scan_katana_max_urls:
            break
    return out_lines[: settings.scan_katana_max_urls], last_res


def run_ffuf_dns(domain: str, wordlist_path: str, max_labels: int) -> tuple[list[str], ToolExecutionResult | None]:
    ffuf = _which_or_none("ffuf")
    if not ffuf or not wordlist_path or not os.path.isfile(wordlist_path):
        return [], None
    fd, path = tempfile.mkstemp(suffix=".json", prefix="ffuf_dns_")
    os.close(fd)
    try:
        result = execute_with_retry(
            "ffuf-dns",
            [
                ffuf,
                "-w",
                wordlist_path,
                "-u",
                f"https://FUZZ.{domain}",
                "-t",
                "25",
                "-mc",
                "200,301,302,403,429",
                "-of",
                "json",
                "-o",
                path,
                "-maxtime",
                "180",
            ],
            timeout_seconds=settings.scan_ffuf_timeout_seconds,
        )
        hosts: list[str] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            for row in (data.get("results") or [])[:max_labels]:
                fuzz = (row.get("input") or {}).get("FUZZ") or ""
                fuzz = str(fuzz).strip().lower()
                if fuzz and "." not in fuzz:
                    hosts.append(f"{fuzz}.{domain.lower().rstrip('.')}")
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
        return hosts, result
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def run_ffuf_dirs(base_url: str, wordlist_path: str, max_matches: int) -> tuple[list[str], ToolExecutionResult | None]:
    ffuf = _which_or_none("ffuf")
    if not ffuf or not wordlist_path or not os.path.isfile(wordlist_path):
        return [], None
    if not base_url.rstrip("/").startswith(tuple(f"{s}://" for s in settings.allowed_schemes)):
        return [], None
    fd, path = tempfile.mkstemp(suffix=".json", prefix="ffuf_dir_")
    os.close(fd)
    base = base_url.rstrip("/") + "/"
    try:
        result = execute_with_retry(
            "ffuf-dir",
            [
                ffuf,
                "-w",
                wordlist_path,
                "-u",
                f"{base}FUZZ",
                "-t",
                "30",
                "-mc",
                "200,301,302,403,401",
                "-of",
                "json",
                "-o",
                path,
                "-maxtime",
                "300",
            ],
            timeout_seconds=settings.scan_ffuf_timeout_seconds,
        )
        urls: list[str] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            for row in (data.get("results") or [])[:max_matches]:
                u = row.get("url") or ""
                if isinstance(u, str) and u.startswith("http"):
                    urls.append(u)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
        return urls, result
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def run_nmap_ports(hosts: list[str], ports: str) -> tuple[str, ToolExecutionResult | None]:
    nmap_bin = _which_or_none("nmap")
    if not nmap_bin or not hosts:
        return "", None
    chunk = hosts[: settings.scan_nmap_max_hosts]
    result = execute_with_retry(
        "nmap",
        [nmap_bin, "-Pn", "-p", ports, "--open", "-oG", "-"] + chunk,
        timeout_seconds=settings.scan_nmap_timeout_seconds,
    )
    return result.stdout or "", result


def run_gowitness_screenshots(hosts_file_lines: list[str], out_dir: str, delay: int) -> tuple[str, ToolExecutionResult | None]:
    gw = _which_or_none("gowitness")
    if not gw or not hosts_file_lines:
        return "", None
    os.makedirs(out_dir, mode=0o755, exist_ok=True)
    fd, list_path = tempfile.mkstemp(suffix=".txt", prefix="gw_hosts_")
    os.close(fd)
    try:
        with open(list_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(hosts_file_lines[:500]))
        result = execute_with_retry(
            "gowitness",
            [gw, "scan", "file", "-f", list_path, "-P", out_dir, "--disable-logging", "--delay", str(delay)],
            timeout_seconds=settings.scan_gowitness_timeout_seconds,
        )
        return out_dir, result
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass


def run_wafw00f_sample(urls: list[str]) -> tuple[str, ToolExecutionResult | None]:
    wf = _which_or_none("wafw00f")
    if not wf or not urls:
        return "", None
    lines: list[str] = []
    last: ToolExecutionResult | None = None
    for url in urls:
        if not url.startswith(tuple(f"{s}://" for s in settings.allowed_schemes)):
            continue
        result = execute_with_retry(
            "wafw00f",
            [wf, url],
            timeout_seconds=settings.scan_wafw00f_timeout_seconds,
        )
        last = result
        if result.stdout:
            lines.append(result.stdout.strip())
    return "\n\n".join(lines), last


def run_sqlmap_batch(url: str) -> tuple[str, ToolExecutionResult | None]:
    sm = _which_or_none("sqlmap")
    if not sm:
        return "", None
    result = execute_with_retry(
        "sqlmap",
        [sm, "-u", url, "--batch", "--level=2", "--risk=2", "--flush-session"],
        timeout_seconds=settings.scan_aggressive_timeout_seconds,
    )
    return result.stdout or "", result


def run_dalfox_url(url: str) -> tuple[str, ToolExecutionResult | None]:
    df = _which_or_none("dalfox")
    if not df:
        return "", None
    result = execute_with_retry(
        "dalfox",
        [df, "url", url, "--silence", "--no-color"],
        timeout_seconds=settings.scan_aggressive_timeout_seconds,
    )
    return result.stdout or "", result


def run_masscan_hosts(hosts: list[str], rate: int) -> tuple[str, ToolExecutionResult | None]:
    ms = _which_or_none("masscan")
    if not ms or not hosts:
        return "", None
    # masscan expects IPs; skip hostnames for safety in v1
    result = execute_with_retry(
        "masscan",
        [ms, hosts[0], "-p1-65535", f"--rate={rate}", "--wait", "5"],
        timeout_seconds=settings.scan_aggressive_timeout_seconds,
    )
    return result.stdout or "", result
