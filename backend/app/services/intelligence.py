from __future__ import annotations

import hashlib
import json
import re
import socket
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.request import Request, urlopen

from app.core.config import settings

STATIC_EXTENSIONS = {
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".webp",
    ".pdf",
    ".mp4",
    ".mp3",
    ".avi",
    ".zip",
}
JS_EXTENSIONS = {".js", ".mjs"}
ADMIN_HINTS = ("admin", "console", "dashboard", "manage", "portal")
LOGIN_HINTS = ("login", "signin", "auth", "oauth", "session", "token", "sso")
API_HINTS = ("api", "graphql", "/v1/", "/v2/", "/rest/")
ENV_PATTERNS = {
    "dev": re.compile(r"(^|[.\-])(dev|qa|test|sandbox|uat|demo)([.\-]|$)"),
    "staging": re.compile(r"(^|[.\-])(stage|staging|preprod)([.\-]|$)"),
    "prod": re.compile(r"(^|[.\-])(prod|production|www|app)([.\-]|$)"),
}
XSS_PARAM_HINTS = {"q", "query", "search", "keyword", "redirect", "return", "next", "url", "callback"}
IDOR_PARAM_HINTS = {"id", "user_id", "account_id", "order_id", "project_id", "invoice_id", "doc_id"}
SSRF_PARAM_HINTS = {"url", "redirect", "next", "dest", "uri", "link", "fetch", "load", "source", "proxy", "endpoint", "host", "server"}
SECRET_PATTERNS = [
    ("api_key", re.compile(r"(?i)(api[_-]?key|token|secret)[\"'`\s:=]{1,8}([A-Za-z0-9_\-]{12,})")),
    ("aws_key", re.compile(r"(AKIA[0-9A-Z]{16})")),
    ("jwt", re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}")),
]
PATH_ENDPOINT_RE = re.compile(r"""(?:"|')((?:https?://[^"'\\\s]+)|(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/\-?]+))(?:\"|')""")


def classify_subdomain(hostname: str, is_live: bool) -> str:
    lowered = hostname.lower()
    for environment, pattern in ENV_PATTERNS.items():
        if pattern.search(lowered):
            return environment
    if is_live:
        return "prod"
    return "unknown"


def auto_tag_subdomain(hostname: str, tech_stack: list[str] | None = None) -> list[str]:
    lowered = hostname.lower()
    tags: set[str] = set()
    if lowered.startswith("www."):
        tags.add("www")
    if "api" in lowered:
        tags.add("api")
    if any(token in lowered for token in ADMIN_HINTS):
        tags.add("admin")
    if any(token in lowered for token in ("dev", "qa", "test", "sandbox", "uat")):
        tags.add("dev")
    if "stage" in lowered:
        tags.add("staging")
    for tech in tech_stack or []:
        low = tech.lower()
        if "wordpress" in low:
            tags.add("wordpress")
        if "nginx" in low:
            tags.add("nginx")
        if "apache" in low:
            tags.add("apache")
        if "cloudflare" in low:
            tags.add("waf")
    return sorted(tags)


def is_takeover_candidate(cname: str | None, is_live: bool) -> bool:
    if is_live or not cname:
        return False
    lowered = cname.lower()
    return any(indicator in lowered for indicator in settings.takeover_indicators)


def resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def _normalize_hostname(parsed) -> tuple[str | None, int | None]:
    if not parsed.hostname:
        return None, None
    host = parsed.hostname.lower()
    port = parsed.port
    if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
        port = None
    return host, port


def _path_suffix(path: str) -> str:
    if "." not in path:
        return ""
    return path[path.rfind(".") :].lower()


def classify_endpoint(normalized_url: str) -> str:
    parsed = urlparse(normalized_url.lower())
    path = parsed.path or "/"
    query = parsed.query
    if any(hint in path for hint in API_HINTS) or path.endswith("/graphql"):
        return "api"
    if any(hint in path for hint in LOGIN_HINTS) or any(key in query for key in ("redirect", "token")):
        return "login"
    if any(hint in path for hint in ADMIN_HINTS):
        return "admin"
    suffix = _path_suffix(path)
    if suffix in STATIC_EXTENSIONS or suffix in JS_EXTENSIONS:
        return "static"
    return "general"


def auto_tag_endpoint(normalized_url: str) -> list[str]:
    parsed = urlparse(normalized_url.lower())
    path = parsed.path or "/"
    suffix = _path_suffix(path)
    tags: set[str] = set()
    category = classify_endpoint(normalized_url)
    if category != "general":
        tags.add(category)
    if "wp-" in path or "wordpress" in path:
        tags.add("wordpress")
    if suffix in JS_EXTENSIONS:
        tags.add("javascript")
    if suffix in STATIC_EXTENSIONS:
        tags.add("static")
    if ".php" in path:
        tags.add("php")
    
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = {key.lower() for key, _ in query_pairs if key}
    if query_keys & SSRF_PARAM_HINTS:
        tags.add("ssrf-candidate")
        
    return sorted(tags)


def compute_priority_score(tags: list[str], query_params: list[str]) -> tuple[int, list[str], bool]:
    score = 0
    reasons: list[str] = []
    tag_set = set(tags)
    if "admin" in tag_set:
        score += 80
        reasons.append("admin surface")
    if "api" in tag_set:
        score += 60
        reasons.append("api surface")
    if "login" in tag_set:
        score += 50
        reasons.append("authentication flow")
    if query_params:
        score += 40
        reasons.append(f"parameterized endpoint ({', '.join(query_params[:4])})")
    if "static" in tag_set:
        score -= 20
        reasons.append("static asset")
    return score, reasons, score >= 60


def normalize_endpoint_url(raw_url: str, *, source: str, js_source: str | None = None) -> dict | None:
    candidate = (raw_url or "").strip()
    if not candidate:
        return None
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in settings.allowed_schemes or not parsed.hostname:
        return None
    hostname, port = _normalize_hostname(parsed)
    if not hostname:
        return None
    path = parsed.path or "/"
    suffix = _path_suffix(path)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = sorted({key for key, _ in query_pairs if key})
    path_part = path.rstrip("/") or "/"
    authority = hostname if port is None else f"{hostname}:{port}"
    normalized_url = f"{parsed.scheme.lower()}://{authority}{path_part}"
    if query_keys:
        normalized_url += "?" + "&".join(query_keys)
    category = classify_endpoint(normalized_url)
    tags = auto_tag_endpoint(normalized_url)
    score, reasons, is_interesting = compute_priority_score(tags, query_keys)
    return {
        "url": candidate,
        "hostname": hostname,
        "normalized_url": normalized_url,
        "path": path_part,
        "query_params": query_keys,
        "priority_score": score,
        "focus_reasons": reasons,
        "source": source,
        "js_source": js_source,
        "category": category,
        "tags": tags,
        "is_interesting": is_interesting,
        "is_static": suffix in STATIC_EXTENSIONS,
        "is_js": suffix in JS_EXTENSIONS,
    }


def normalize_and_dedupe_urls(raw_urls: list[str], *, source: str, js_source: str | None = None) -> list[dict]:
    deduped: dict[str, dict] = {}
    for raw_url in raw_urls:
        record = normalize_endpoint_url(raw_url, source=source, js_source=js_source)
        if not record:
            continue
        key = record["normalized_url"]
        existing = deduped.get(key)
        if not existing:
            deduped[key] = record
            continue
        existing["priority_score"] = max(existing["priority_score"], record["priority_score"])
        existing["focus_reasons"] = sorted(set(existing["focus_reasons"]) | set(record["focus_reasons"]))
        existing["tags"] = sorted(set(existing["tags"]) | set(record["tags"]))
        existing["is_interesting"] = existing["is_interesting"] or record["is_interesting"]
        if existing["source"] == "gau" and source == "js":
            if record["js_source"]:
                existing["js_source"] = record["js_source"]
        elif existing["source"] == "js" and source == "gau":
            existing["source"] = "gau"
    return sorted(deduped.values(), key=lambda item: (item["hostname"], item["path"], item["normalized_url"]))


def filter_nuclei_targets(endpoints: list[dict]) -> list[str]:
    targets: list[str] = []
    for endpoint in sorted(endpoints, key=lambda item: (-item["priority_score"], item["normalized_url"])):
        if endpoint["is_static"]:
            continue
        targets.append(endpoint["url"])
    return targets[: settings.scan_nuclei_target_cap]


def select_javascript_assets(endpoints: list[dict]) -> list[dict]:
    candidates = [endpoint for endpoint in endpoints if endpoint["is_js"]]
    return sorted(candidates, key=lambda item: (-item["priority_score"], item["normalized_url"]))[: settings.js_fetch_max_assets]


def fetch_javascript_asset(url: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    request = Request(url, headers={"User-Agent": "ReconX Elite"})
    try:
        with urlopen(request, timeout=settings.js_fetch_timeout_seconds) as response:
            body = response.read(settings.js_fetch_max_bytes + 1)
        if len(body) > settings.js_fetch_max_bytes:
            warnings.append("asset truncated at configured byte cap")
            body = body[: settings.js_fetch_max_bytes]
        return body.decode("utf-8", errors="ignore"), warnings
    except OSError as exc:
        warnings.append(str(exc))
        return "", warnings


def extract_endpoints_from_javascript(text: str, asset_url: str, in_scope_hosts: set[str]) -> list[str]:
    matches: list[str] = []
    for match in PATH_ENDPOINT_RE.findall(text[: settings.js_fetch_max_bytes]):
        candidate = match.strip()
        if candidate.startswith("//"):
            continue
        absolute = urljoin(asset_url, candidate)
        parsed = urlparse(absolute)
        if parsed.hostname and parsed.hostname.lower() in in_scope_hosts:
            matches.append(absolute)
        if len(matches) >= 100:
            break
    return sorted(set(matches))


def extract_secret_like_strings(text: str) -> list[dict]:
    results: list[dict] = []
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            secret = match.group(match.lastindex or 1)
            results.append(
                {
                    "kind": kind,
                    "snippet": secret[:48],
                    "sha256": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                }
            )
            if len(results) >= 20:
                return results
    return results


def analyze_javascript_assets(candidates: list[dict], in_scope_hosts: set[str]) -> tuple[list[dict], list[dict]]:
    asset_rows: list[dict] = []
    derived_endpoints: list[dict] = []
    for candidate in candidates:
        content, warnings = fetch_javascript_asset(candidate["url"])
        extracted_endpoints = extract_endpoints_from_javascript(content, candidate["url"], in_scope_hosts) if content else []
        secrets = extract_secret_like_strings(content) if content else []
        asset_rows.append(
            {
                "url": candidate["url"],
                "normalized_url": candidate["normalized_url"],
                "hostname": candidate["hostname"],
                "source_endpoint_url": candidate["url"],
                "status": "fetched" if content else "failed",
                "extracted_endpoints": extracted_endpoints,
                "secrets_json": secrets,
                "warnings_json": warnings,
                "metadata_json": {"content_length": len(content), "secret_count": len(secrets)},
                "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest() if content else None,
            }
        )
        derived_endpoints.extend(
            normalize_and_dedupe_urls(extracted_endpoints, source="js", js_source=candidate["url"])
        )
    return asset_rows, derived_endpoints


def build_subdomain_record(hostname: str, enrich_data: dict[str, dict], live_hosts: set[str]) -> dict:
    enriched = enrich_data.get(hostname, {})
    is_live = hostname in live_hosts
    tech_stack = enriched.get("tech_stack") or []
    ip = enriched.get("ip") or resolve_ip(hostname)
    cname = enriched.get("cname")
    tags = auto_tag_subdomain(hostname, tech_stack)
    environment = classify_subdomain(hostname, is_live)
    return {
        "hostname": hostname,
        "is_live": is_live,
        "environment": environment,
        "tags": tags,
        "takeover_candidate": is_takeover_candidate(cname, is_live),
        "cname": cname,
        "ip": ip,
        "tech_stack": tech_stack,
        "cdn": enriched.get("cdn"),
        "waf": enriched.get("waf"),
        "cdn_waf": enriched.get("cdn_waf"),
    }


def synthesize_heuristic_findings(endpoints: list, javascript_assets: list, subdomains: list) -> list[dict]:
    findings: list[dict] = []
    waf_present = any((row.waf or row.cdn_waf) for row in subdomains)
    secret_assets = [asset for asset in javascript_assets if asset.secrets_json]
    for endpoint in endpoints:
        params = set(endpoint.query_params or [])
        tags = set(endpoint.tags or [])
        evidence_base = {
            "endpoint_id": endpoint.id,
            "normalized_url": endpoint.normalized_url,
            "focus_reasons": endpoint.focus_reasons or [],
        }
        if params & XSS_PARAM_HINTS:
            findings.append(
                {
                    "template_id": "reconx-heuristic-xss-candidate",
                    "severity": "medium",
                    "source": "heuristic",
                    "confidence": 0.62,
                    "matcher_name": "xss-candidate",
                    "matched_url": endpoint.url,
                    "host": endpoint.hostname,
                    "description": "Endpoint exposes reflected-style parameters often associated with XSS testing.",
                    "evidence_json": evidence_base | {"matched_params": sorted(params & XSS_PARAM_HINTS)},
                }
            )
        if params & IDOR_PARAM_HINTS or any(token in (endpoint.path or "") for token in ("/user/", "/account/", "/project/")):
            findings.append(
                {
                    "template_id": "reconx-heuristic-idor-candidate",
                    "severity": "high" if "admin" in tags else "medium",
                    "source": "heuristic",
                    "confidence": 0.67,
                    "matcher_name": "idor-candidate",
                    "matched_url": endpoint.url,
                    "host": endpoint.hostname,
                    "description": "Endpoint looks parameterized around object identifiers and should be reviewed for access-control bypass.",
                    "evidence_json": evidence_base | {"matched_params": sorted(params & IDOR_PARAM_HINTS)},
                }
            )
        if params & SSRF_PARAM_HINTS:
            findings.append(
                {
                    "template_id": "reconx-heuristic-ssrf-candidate",
                    "severity": "high",
                    "source": "heuristic",
                    "confidence": 0.65,
                    "matcher_name": "ssrf-candidate",
                    "matched_url": endpoint.url,
                    "host": endpoint.hostname,
                    "description": "Endpoint exposes parameters commonly used for URL redirection or fetching remote resources.",
                    "evidence_json": evidence_base | {"matched_params": sorted(params & SSRF_PARAM_HINTS)},
                }
            )
        if "login" in tags or "auth" in (endpoint.path or ""):
            findings.append(
                {
                    "template_id": "reconx-heuristic-bruteforce-candidate",
                    "severity": "medium",
                    "source": "heuristic",
                    "confidence": 0.58 if waf_present else 0.65,
                    "matcher_name": "bruteforce-candidate",
                    "matched_url": endpoint.url,
                    "host": endpoint.hostname,
                    "description": "Authentication endpoint detected; rate-limiting and lockout controls should be reviewed.",
                    "evidence_json": evidence_base | {"waf_present": waf_present},
                }
            )
    for asset in secret_assets:
        findings.append(
            {
                "template_id": "reconx-heuristic-js-secret-candidate",
                "severity": "high",
                "source": "heuristic",
                "confidence": 0.71,
                "matcher_name": "javascript-secret-candidate",
                "matched_url": asset.url,
                "host": asset.hostname,
                "description": "JavaScript asset contains secret-like material that merits manual validation.",
                "evidence_json": {"secrets_json": asset.secrets_json},
            }
        )
    return findings


def rank_attack_paths(endpoints: list, vulnerabilities: list) -> list[dict]:
    by_url: dict[str, list] = defaultdict(list)
    for vulnerability in vulnerabilities:
        key = vulnerability.matched_url or vulnerability.host or ""
        by_url[key].append(vulnerability)

    attack_paths: list[dict] = []
    severity_weights = {"critical": 120, "high": 90, "medium": 60, "low": 30, "info": 10}
    for endpoint in endpoints:
        related = by_url.get(endpoint.url, []) + by_url.get(endpoint.normalized_url, [])
        if not related and endpoint.priority_score < 60:
            continue
        highest = max((severity_weights.get(vulnerability.severity, 20) for vulnerability in related), default=20)
        score = endpoint.priority_score + highest
        severity = "medium"
        if score >= 170:
            severity = "critical"
        elif score >= 140:
            severity = "high"
        elif score >= 90:
            severity = "medium"
        else:
            severity = "low"
        steps = [{"kind": "pivot", "value": endpoint.url}]
        for vulnerability in related[:4]:
            steps.append(
                {
                    "kind": vulnerability.source,
                    "value": vulnerability.template_id,
                    "severity": vulnerability.severity,
                }
            )
        attack_paths.append(
            {
                "title": f"Prioritized path via {endpoint.hostname or endpoint.url}",
                "summary": (
                    f"Endpoint scored {endpoint.priority_score} with {len(related)} correlated finding(s); "
                    "use it as a first-pass manual validation target."
                ),
                "severity": severity,
                "score": score,
                "evidence_json": {
                    "endpoint_id": endpoint.id,
                    "endpoint_priority": endpoint.priority_score,
                    "focus_reasons": endpoint.focus_reasons or [],
                    "finding_count": len(related),
                },
                "steps_json": steps,
            }
        )
    attack_paths.sort(key=lambda row: (-row["score"], row["title"]))
    return attack_paths[:25]
