"""Passive subdomain discovery (crt.sh, optional github-subdomains CLI)."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Iterable

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

DOMAIN_PART = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]+)*$")


def _under_root(hostname: str, root: str) -> bool:
    h = hostname.lower().rstrip(".")
    r = root.lower().rstrip(".")
    return h == r or h.endswith("." + r)


def normalize_passive_hosts(hosts: Iterable[str], root_domain: str) -> list[str]:
    seen: dict[str, str] = {}
    for raw in hosts:
        h = (raw or "").strip().lower().rstrip(".")
        if not h:
            continue
        if h.startswith("*."):
            h = h[2:]
        if not h or " " in h or "*" in h:
            continue
        if not _under_root(h, root_domain):
            continue
        if not DOMAIN_PART.match(h):
            continue
        seen[h] = h
    return sorted(seen.keys())


def fetch_crtsh_subdomains(domain: str) -> list[str]:
    """Query crt.sh JSON API; capped by settings."""
    cap = settings.scan_crtsh_max_names
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with httpx.Client(
            timeout=settings.scan_crtsh_timeout_seconds, follow_redirects=True
        ) as client:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.warning("crt.sh fetch failed for %s: %s", domain, exc)
        return []

    if not isinstance(data, list):
        return []

    names: list[str] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        nv = row.get("name_value") or ""
        for part in str(nv).splitlines():
            part = part.strip()
            if part:
                names.append(part)
            if len(names) >= cap * 2:
                break
        if len(names) >= cap * 2:
            break

    out = normalize_passive_hosts(names, domain)[:cap]
    return out


def run_github_subdomains_cli(domain: str) -> list[str]:
    """If `github-subdomains` is on PATH and token is set, collect hostnames."""
    if not settings.github_token:
        return []
    binary = shutil.which("github-subdomains")
    if not binary:
        logger.info("github-subdomains binary not found; skipping")
        return []
    cap = settings.scan_github_subdomains_max_names
    try:
        proc = subprocess.run(
            [binary, "-d", domain, "-t", settings.github_token, "-silent"],
            capture_output=True,
            text=True,
            timeout=settings.scan_github_subdomains_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("github-subdomains timed out for %s", domain)
        return []

    if proc.returncode != 0:
        logger.warning(
            "github-subdomains failed: %s",
            proc.stderr[:500] if proc.stderr else proc.returncode,
        )
        return []

    hosts = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    return normalize_passive_hosts(hosts, domain)[:cap]
