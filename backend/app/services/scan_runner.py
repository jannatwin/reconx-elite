import json
import shlex
import subprocess
from typing import Any

from app.core.config import settings


def run_command(command: list[str]) -> tuple[list[str], str | None]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [], f"tool_not_found:{command[0]}"

    if proc.returncode != 0:
        return [], f"command_failed:{' '.join(shlex.quote(c) for c in command)}:{proc.stderr.strip()}"
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return lines, None


def run_subfinder(domain: str) -> tuple[list[str], str | None]:
    return run_command(["subfinder", "-silent", "-d", domain])


def run_httpx(hosts: list[str]) -> tuple[list[str], str | None]:
    if not hosts:
        return [], None
    command = ["httpx", "-silent", "-json"]
    try:
        proc = subprocess.run(
            command,
            input="\n".join(hosts) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return [], "tool_not_found:httpx"

    if proc.returncode != 0:
        return [], f"command_failed:httpx:{proc.stderr.strip()}"

    live_hosts = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            host = payload.get("input")
            if host:
                live_hosts.append(host)
        except json.JSONDecodeError:
            continue
    return sorted(set(live_hosts)), None


def run_gau(domain: str) -> tuple[list[str], str | None]:
    return run_command(["gau", "--subs", domain])


def run_nuclei(targets: list[str]) -> tuple[list[dict[str, Any]], str | None]:
    if not targets:
        return [], None

    command = ["nuclei", "-silent", "-jsonl"]
    if settings.nuclei_templates:
        command.extend(["-t", settings.nuclei_templates])

    try:
        proc = subprocess.run(
            command,
            input="\n".join(targets) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return [], "tool_not_found:nuclei"

    if proc.returncode != 0:
        return [], f"command_failed:nuclei:{proc.stderr.strip()}"

    vulns: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {})
        vulns.append(
            {
                "template_id": data.get("template-id", "unknown-template"),
                "severity": info.get("severity", "unknown"),
                "matcher_name": data.get("matcher-name"),
                "host": data.get("host"),
                "description": info.get("description"),
            }
        )
    return vulns, None


def check_headers(urls: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    scheme_allow = tuple(s.strip() + "://" for s in settings.scan_allowed_schemes.split(","))
    for url in urls:
        if not url.startswith(scheme_allow):
            continue
        command = ["httpx", "-silent", "-json", "-H", "User-Agent: ReconX", "-u", url]
        rows, err = run_command(command)
        if err:
            continue
        for row in rows:
            try:
                data = json.loads(row)
            except json.JSONDecodeError:
                continue
            headers = {k.lower(): v for k, v in (data.get("header") or {}).items()}
            missing = []
            for key in ("content-security-policy", "x-frame-options", "strict-transport-security"):
                if key not in headers:
                    missing.append(key)
            if missing:
                findings.append(
                    {
                        "template_id": "reconx-missing-security-headers",
                        "severity": "info",
                        "matcher_name": "missing-headers",
                        "host": data.get("url") or url,
                        "description": f"Missing security headers: {', '.join(missing)}",
                    }
                )
    return findings
