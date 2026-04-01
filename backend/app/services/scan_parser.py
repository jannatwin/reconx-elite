import json
from typing import Any


def parse_subfinder_output(stdout: str) -> list[str]:
    return sorted({line.strip().lower() for line in stdout.splitlines() if line.strip()})


def parse_httpx_live_output(stdout: str) -> list[str]:
    hosts: set[str] = set()
    for line in stdout.splitlines():
        row = line.strip()
        if not row:
            continue
        try:
            payload = json.loads(row)
        except json.JSONDecodeError:
            continue
        host = (payload.get("input") or "").strip().lower()
        if host:
            hosts.add(host)
    return sorted(hosts)


def parse_httpx_enrich_output(stdout: str) -> dict[str, dict]:
    enrich_data: dict[str, dict] = {}
    known_cdn_waf = {"cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "sucuri", "imperva", "stackpath"}
    for line in stdout.splitlines():
        row = line.strip()
        if not row:
            continue
        try:
            payload = json.loads(row)
        except json.JSONDecodeError:
            continue
        host = (payload.get("input") or "").strip().lower()
        if host:
            tech = payload.get("tech", [])
            cdn_data = payload.get("cdn")
            cdn = cdn_data.get("name") if isinstance(cdn_data, dict) else cdn_data
            waf = None
            for t in tech:
                if t.lower() in known_cdn_waf:
                    waf = t
                    break
            cdn_waf = cdn or waf
            cname = payload.get("cname")
            if isinstance(cname, list):
                cname = cname[0] if cname else None
            enrich_data[host] = {
                "ip": payload.get("a", [None])[0] if payload.get("a") else None,
                "tech_stack": tech,
                "cdn": cdn,
                "waf": waf,
                "cdn_waf": cdn_waf,
                "cname": cname,
                "status_code": payload.get("status_code"),
                "title": payload.get("title"),
            }
    return enrich_data


def parse_gau_output(stdout: str) -> list[str]:
    return sorted({line.strip() for line in stdout.splitlines() if line.strip()})


def parse_nuclei_output(stdout: str) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for line in stdout.splitlines():
        row = line.strip()
        if not row:
            continue
        try:
            data = json.loads(row)
        except json.JSONDecodeError:
            continue
        info = data.get("info") or {}
        host = data.get("host") or ""
        matched_url = data.get("matched-at") or data.get("url") or host
        template_id = data.get("template-id", "unknown-template")
        matcher_name = data.get("matcher-name") or ""
        key = (template_id, matched_url or "", matcher_name)
        if key in seen:
            continue
        seen.add(key)
        vulns.append(
            {
                "template_id": template_id,
                "severity": info.get("severity", "unknown"),
                "source": "nuclei",
                "confidence": 0.92,
                "matcher_name": matcher_name or None,
                "matched_url": matched_url or None,
                "host": host or None,
                "description": info.get("description"),
                "evidence_json": {
                    "name": info.get("name"),
                    "tags": info.get("tags") or [],
                    "reference": info.get("reference") or [],
                    "classification": info.get("classification") or {},
                },
            }
        )
    return vulns


def parse_httpx_headers_output(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        row = line.strip()
        if not row:
            continue
        try:
            data = json.loads(row)
        except json.JSONDecodeError:
            continue
        headers = {k.lower(): v for k, v in (data.get("header") or {}).items()}
        missing = [k for k in ("content-security-policy", "x-frame-options", "strict-transport-security") if k not in headers]
        if not missing:
            continue
        host = data.get("url") or data.get("input") or ""
        if host in seen:
            continue
        seen.add(host)
        findings.append(
            {
                "template_id": "reconx-missing-security-headers",
                "severity": "info",
                "source": "heuristic",
                "confidence": 0.45,
                "matcher_name": "missing-headers",
                "host": host or None,
                "description": f"Missing security headers: {', '.join(missing)}",
                "evidence_json": {"missing_headers": missing},
            }
        )
    return findings
