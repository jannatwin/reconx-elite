"""AI service for ReconX Elite multi-model orchestration and verification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import google.generativeai as genai
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

MODEL_MAP = {
    "orchestrator": "meta-llama/nemotron-3-nano-30b-a3b",
    "primary_analyst": "meta-llama/llama-3.3-70b-instruct",
    "deep_analyst": "openai/gpt-4o",
    "fast_analyst": "openai/gpt-3.5-turbo",
    "chain_reasoner": "nvidia/nemotron-3-super",
    "code_engine": "qwen/qwen3-coder-480b-a35b",
    "js_reader": "minimax/minimax-m2.5",
    "fast_classifier": "thudm/glm-4.5-air",
    "structured_output": "google/gemma-4-26b-a4b",
    "misconfig_analyst": "google/gemma-4-31b",
}

TASK_ROLE_MAP = {
    "scan": "structured_output",
    "analyze": "primary_analyst",
    "report": "deep_analyst",
    "triage": "fast_classifier",
    "js": "js_reader",
    "payload": "code_engine",
    "severity": "primary_analyst",
    "chain": "chain_reasoner",
    "misconfig": "misconfig_analyst",
}

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_RATE_LIMIT_EVENTS: deque[float] = deque()
_MODEL_STATUS_CACHE: dict[str, Any] = {"updated_at": None, "results": {}}

ORCHESTRATOR_SYSTEM_PROMPT = """
You are the master orchestration agent for ReconX-Elite, a professional
bug bounty hunting AI system. You coordinate ten specialized models.
You never answer security questions directly. You always route tasks
to the correct model using the rules below. You speak in structured
JSON routing instructions only.

YOUR ROUTING RULES:

SUBDOMAIN TRIAGE -> fast_classifier (glm-4.5-air)
  Classify each host as: auth_target, api_target, admin_target,
  dev_target, or skip. Return JSON array only.

RAW OUTPUT PARSING -> structured_output (gemma-4-26b-a4b)
  Extract fields from subfinder, httpx, nuclei, gau, ffuf output.
  Return clean JSON. No markdown. No explanation.

JS FILE ANALYSIS -> js_reader (minimax-m2.5)
  Use for all JS files over 10KB. Extract: hidden endpoints,
  hardcoded secrets, internal URLs, auth logic. Return JSON.

IDOR TEST GENERATION -> primary_analyst (llama-3.3-70b-instruct)
  Generate complete IDOR and access control test cases.
  Include exact HTTP requests, vulnerable vs secure response patterns.

JWT ATTACK ANALYSIS -> chain_reasoner (nemotron-3-super)
  Analyze JWT token. Check: alg field, kid injection, HS256 confusion,
  brute force viability. Provide step-by-step exploit path.

SSRF ESCALATION -> chain_reasoner (nemotron-3-super)
  Plan full escalation from SSRF callback to cloud credential theft.
  Provide exact URLs and curl commands for each step.

XSS PAYLOADS -> code_engine (qwen3-coder-480b-a35b)
  Generate context-specific payloads with WAF bypass variants.
  Return as JSON array ranked by bypass probability.

SQLI PAYLOADS -> code_engine (qwen3-coder-480b-a35b)
  Generate DB-specific payloads. Include sqlmap command. Return JSON.

HEADER AND CORS ANALYSIS -> misconfig_analyst (gemma-4-31b)
  Analyze full HTTP headers for CORS, CSP, clickjacking, cache issues.
  Return JSON findings array with severity and remediation.

VULNERABILITY CHAINING -> chain_reasoner (nemotron-3-super)
  Review all findings. Identify chain combinations.
  Rate combined severity. Write attack narrative for each chain.

BUSINESS LOGIC ANALYSIS -> deep_analyst (gpt-4o)
  Analyze application features for logic flaws, race conditions,
  workflow bypass, price manipulation, role escalation.

SEVERITY RATING -> primary_analyst (llama-3.3-70b-instruct)
  Rate using CVSS v3.1. Return score, vector, label, justification.

LOW/MEDIUM REPORTS -> fast_analyst (gpt-3.5-turbo)
  Write complete HackerOne-format report for Medium and Low findings.

HIGH/CRITICAL REPORTS -> deep_analyst (gpt-4o)
  Write complete HackerOne-format report for High and Critical findings.
  Never use fast_analyst for Critical findings.

EXECUTIVE SUMMARY -> deep_analyst (gpt-4o)
  Write CISO-level summary of all findings after assessment completes.

HARD STOPS - NEVER VIOLATE:
  - If target is not in scope list, stop and log, do not route any task
  - If secrets found in JS, set escalate=CRITICAL immediately
  - Never report nuclei findings without manual confirmation
  - Never use fast_analyst for High or Critical severity reports
  - Always load API keys from environment variables, never hardcode
"""


class AIProvider:
    async def generate_content_async(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        model_id: Optional[str] = None,
        response_mime_type: str = "application/json",
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        raise NotImplementedError


class GeminiProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        if api_key:
            genai.configure(api_key=api_key)
        else:
            logger.warning("GEMINI_API_KEY not configured - Gemini features disabled")

    async def generate_content_async(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        model_id: Optional[str] = None,
        response_mime_type: str = "application/json",
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        if not self.api_key:
            raise ValueError("Gemini API key not configured")

        target_model = model_id or settings.ai_scan_model or "gemini-1.5-flash"
        model = genai.GenerativeModel(
            model_name=target_model,
            system_instruction=system_instruction,
            generation_config={
                "temperature": temperature,
                "response_mime_type": response_mime_type,
            },
        )
        response = await model.generate_content_async(prompt)
        usage = {}
        usage_metadata = getattr(response, "usage_metadata", None)
        if usage_metadata:
            usage = {
                "prompt_tokens": getattr(usage_metadata, "prompt_token_count", None),
                "completion_tokens": getattr(usage_metadata, "candidates_token_count", None),
                "total_tokens": getattr(usage_metadata, "total_token_count", None),
            }
        return {"output": response.text or "", "usage": usage}


class OpenRouterProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        if not api_key:
            logger.warning("OPENROUTER_KEY not configured - OpenRouter features disabled")

    async def generate_content_async(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        model_id: Optional[str] = None,
        response_mime_type: str = "application/json",
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        if not self.api_key:
            raise ValueError("OpenRouter API key not configured")

        target_model = model_id or MODEL_MAP["orchestrator"]
        messages: list[dict[str, str]] = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "temperature": temperature,
        }
        if response_mime_type == "application/json":
            payload["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{OPENROUTER_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://reconx-elite.local",
                    "X-Title": "ReconX Elite",
                },
                json=payload,
            )
            response.raise_for_status()
            result = response.json()
        return {
            "output": result["choices"][0]["message"]["content"],
            "usage": result.get("usage") or {},
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json_payload(text: str) -> Any:
    candidate = (text or "").strip()
    if not candidate:
        return {}
    if candidate.startswith("```"):
        candidate = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", candidate)
        candidate = re.sub(r"\s*```$", "", candidate)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        match = re.search(r"(\{.*\}|\[.*\])", candidate, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(1))


def _parse_rate_limit(value: str) -> tuple[int, float]:
    match = re.fullmatch(r"\s*(\d+)\s*/\s*(second|minute|hour)\s*", value or "")
    if not match:
        return 9999, 60.0
    limit = int(match.group(1))
    unit = match.group(2)
    seconds = {"second": 1.0, "minute": 60.0, "hour": 3600.0}[unit]
    return limit, seconds


def _check_rate_limit() -> bool:
    limit, window = _parse_rate_limit(settings.ai_rate_limit)
    now = time.time()
    while _RATE_LIMIT_EVENTS and (now - _RATE_LIMIT_EVENTS[0]) > window:
        _RATE_LIMIT_EVENTS.popleft()
    if len(_RATE_LIMIT_EVENTS) >= limit:
        return False
    _RATE_LIMIT_EVENTS.append(now)
    return True


def _default_role_for_task(task: str) -> str:
    return TASK_ROLE_MAP.get(task, "orchestrator")


def _get_model(task: str = "scan", role: str | None = None) -> AIProvider:
    return get_ai_provider(role or _default_role_for_task(task))


def _is_ai_enabled(task: str = "scan") -> bool:
    if task == "report":
        return bool(settings.openrouter_key or settings.gemini_api_key or settings.ai_report_model)
    if task == "analyze":
        return bool(settings.openrouter_key or settings.gemini_api_key or settings.ai_analyze_model)
    return bool(settings.openrouter_key or settings.gemini_api_key or settings.ai_scan_model)


def get_ai_provider(role: str = "orchestrator") -> AIProvider:
    if settings.openrouter_key:
        return OpenRouterProvider(settings.openrouter_key)
    return GeminiProvider(settings.gemini_api_key)


def _record_agent_event(payload: dict[str, Any]) -> None:
    try:
        from app.services.websocket import record_agent_log_event

        record_agent_log_event(payload)
    except Exception:
        logger.debug("agent log history unavailable", exc_info=True)


def _emit_agent_event(payload: dict[str, Any]) -> None:
    _record_agent_event(payload)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    try:
        from app.services.websocket import publish_agent_log_event

        loop.create_task(publish_agent_log_event(payload))
    except Exception:
        logger.debug("agent log publish unavailable", exc_info=True)


async def call_model(
    role: str,
    prompt: str,
    system_instruction: Optional[str] = None,
    response_mime_type: str = "application/json",
    temperature: float = 0.1,
    task: str | None = None,
) -> dict[str, Any]:
    model_id = MODEL_MAP.get(role)
    if not model_id:
        raise ValueError(f"Unknown model role: {role}")
    provider = get_ai_provider(role)
    _emit_agent_event(
        {
            "event": "model_call_started",
            "timestamp": _utc_now(),
            "role": role,
            "model_id": model_id,
            "task": task or role,
            "status": "started",
            "success": True,
        }
    )
    try:
        result = await provider.generate_content_async(
            prompt=prompt,
            system_instruction=system_instruction,
            model_id=model_id,
            response_mime_type=response_mime_type,
            temperature=temperature,
        )
        payload = {
            "role": role,
            "model_id": model_id,
            "provider": provider.__class__.__name__.replace("Provider", ""),
            "output": result.get("output", ""),
            "usage": result.get("usage") or {},
        }
        _emit_agent_event(
            {
                "event": "model_call_completed",
                "timestamp": _utc_now(),
                "role": role,
                "model_id": model_id,
                "task": task or role,
                "status": "completed",
                "success": True,
                "tokens_used": payload["usage"].get("total_tokens"),
            }
        )
        return payload
    except Exception as exc:
        _emit_agent_event(
            {
                "event": "model_call_failed",
                "timestamp": _utc_now(),
                "role": role,
                "model_id": model_id,
                "task": task or role,
                "status": "failed",
                "success": False,
                "error": str(exc),
            }
        )
        raise


async def _get_model_response(
    prompt: str,
    system_instruction: Optional[str] = None,
    task: str = "scan",
    role: str | None = None,
    response_mime_type: str = "application/json",
    temperature: float = 0.1,
) -> str:
    result = await call_model(
        role=role or _default_role_for_task(task),
        prompt=prompt,
        system_instruction=system_instruction,
        response_mime_type=response_mime_type,
        temperature=temperature,
        task=task,
    )
    return result["output"]


def _normalize_template_list(values: Any) -> list[str]:
    out: list[str] = []
    for value in values or []:
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return list(dict.fromkeys(out))


def _merge_high_value_targets_by_url(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for target in targets:
        url = str(target.get("url") or "").strip()
        if not url:
            continue
        priority = max(1, min(int(target.get("priority") or 5), 10))
        normalized = {
            "url": url,
            "reason": str(target.get("reason") or "").strip() or "High-value target",
            "priority": priority,
            "classification": str(target.get("classification") or "").strip() or "target",
            "source": str(target.get("source") or "").strip() or "ai",
        }
        existing = merged.get(url)
        if not existing or priority > existing["priority"]:
            merged[url] = normalized
    return sorted(merged.values(), key=lambda item: (-item["priority"], item["url"]))


def _merge_potential_leaks(leaks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for leak in leaks:
        leak_type = str(leak.get("type") or "").strip() or "unknown"
        detail = str(leak.get("detail") or "").strip()
        if not detail:
            continue
        key = (leak_type, detail)
        merged[key] = {
            "type": leak_type,
            "detail": detail,
            "severity": str(leak.get("severity") or "").strip() or "medium",
            "location": str(leak.get("location") or "").strip() or "",
        }
    return list(merged.values())


def _validate_ai_scan_response(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {
            "high_value_targets": [],
            "potential_leaks": [],
            "juicy_js_files": [],
            "suggested_nuclei_templates": [],
            "security_flags": [],
            "confidence_score": "low",
            "total_processed": 0,
            "batches_processed": 0,
        }

    allowed = {
        "high_value_targets",
        "potential_leaks",
        "juicy_js_files",
        "suggested_nuclei_templates",
        "security_flags",
        "confidence_score",
        "total_processed",
        "batches_processed",
    }
    cleaned = {key: raw[key] for key in allowed if key in raw}
    high_value_targets = [item for item in cleaned.get("high_value_targets", []) if isinstance(item, dict)]
    cleaned["high_value_targets"] = _merge_high_value_targets_by_url(high_value_targets)
    cleaned["potential_leaks"] = _merge_potential_leaks(
        [item for item in cleaned.get("potential_leaks", []) if isinstance(item, dict)]
    )
    cleaned["juicy_js_files"] = [
        {
            "url": str(item.get("url") or "").strip(),
            "rationale": str(item.get("rationale") or "").strip(),
            "focus_areas": str(item.get("focus_areas") or "").strip(),
        }
        for item in cleaned.get("juicy_js_files", [])
        if isinstance(item, dict) and str(item.get("url") or "").strip()
    ]
    cleaned["suggested_nuclei_templates"] = _normalize_template_list(cleaned.get("suggested_nuclei_templates", []))
    cleaned["security_flags"] = _normalize_template_list(cleaned.get("security_flags", []))
    cleaned["confidence_score"] = str(cleaned.get("confidence_score") or "low").lower()
    cleaned["total_processed"] = int(cleaned.get("total_processed") or 0)
    cleaned["batches_processed"] = int(cleaned.get("batches_processed") or 0)
    return cleaned


def build_javascript_asset_summaries_for_ai(asset_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for row in asset_rows:
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        extracted_endpoints = list(row.get("extracted_endpoints") or [])
        path_prefixes = []
        for endpoint in extracted_endpoints:
            if not isinstance(endpoint, str):
                continue
            parsed = urlparse(endpoint)
            path_prefixes.append(parsed.path or endpoint)
        summaries.append(
            {
                "url": url,
                "secret_count": len(row.get("secrets_json") or []),
                "extracted_endpoint_count": len(extracted_endpoints),
                "path_prefix_samples": list(dict.fromkeys(path_prefixes))[:5],
            }
        )
    return summaries


def _triage_host(host: str) -> tuple[str, str]:
    lowered = host.lower()
    if any(token in lowered for token in ("auth", "login", "signin", "sso", "oauth", "account")):
        return "auth_target", "Authentication-related host"
    if any(token in lowered for token in ("api", "graphql", "rest")):
        return "api_target", "API-related host"
    if any(token in lowered for token in ("admin", "manage", "console", "portal")):
        return "admin_target", "Administrative host"
    if any(token in lowered for token in ("dev", "test", "stage", "staging", "sandbox", "qa")):
        return "dev_target", "Development or staging host"
    return "skip", "No elevated signal"


def triage_hosts(hosts: list[str]) -> list[dict[str, Any]]:
    triaged: list[dict[str, Any]] = []
    for host in hosts:
        classification, reason = _triage_host(host)
        triaged.append({"host": host, "classification": classification, "reason": reason})
    return triaged


def _ai_scan_fallback(hosts: list[str], source: str) -> dict[str, Any]:
    high_value_targets = []
    potential_leaks = []
    suggested_templates: list[str] = []
    for item in triage_hosts(hosts):
        if item["classification"] != "skip":
            priority = {
                "admin_target": 9,
                "auth_target": 8,
                "api_target": 7,
                "dev_target": 6,
            }.get(item["classification"], 5)
            high_value_targets.append(
                {
                    "url": item["host"],
                    "reason": item["reason"],
                    "priority": priority,
                    "classification": item["classification"],
                    "source": source,
                }
            )
        lowered = item["host"].lower()
        if any(token in lowered for token in ("internal", "debug", "staging", "dev")):
            potential_leaks.append({"type": "host", "detail": item["host"], "severity": "medium"})
        if "api" in lowered:
            suggested_templates.append("misconfiguration/http/cors-misconfig.yaml")
        if "admin" in lowered:
            suggested_templates.append("http/exposed-panels/admin-login-panel.yaml")
    return _validate_ai_scan_response(
        {
            "high_value_targets": high_value_targets,
            "potential_leaks": potential_leaks,
            "suggested_nuclei_templates": suggested_templates,
            "confidence_score": "medium",
            "total_processed": len(hosts),
            "batches_processed": 1 if hosts else 0,
        }
    )


async def analyze_subdomains(hosts: list[str]) -> dict[str, Any]:
    fallback = _ai_scan_fallback(hosts, "subdomains")
    if not hosts or not _is_ai_enabled("scan") or not _check_rate_limit():
        return fallback
    prompt = json.dumps({"hosts": hosts, "task": "subdomain_triage"})
    try:
        output = await _get_model_response(prompt, task="triage", role="fast_classifier")
        parsed = _parse_json_payload(output)
        if isinstance(parsed, list):
            fallback["high_value_targets"] = _merge_high_value_targets_by_url(
                [
                    {
                        "url": item.get("host") or item.get("url"),
                        "reason": item.get("reason") or "AI triage",
                        "priority": item.get("priority") or 5,
                        "classification": item.get("classification") or "target",
                        "source": "ai",
                    }
                    for item in parsed
                    if isinstance(item, dict)
                ]
            )
            return fallback
        return _validate_ai_scan_response(parsed)
    except Exception:
        logger.warning("Falling back to local subdomain analysis", exc_info=True)
        return fallback


async def analyze_live_hosts(httpx_output: str) -> dict[str, Any]:
    hosts = []
    for line in (httpx_output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = urlparse(line if "://" in line else f"https://{line}")
        hosts.append(parsed.hostname or line)
    return await analyze_subdomains(list(dict.fromkeys(hosts)))


async def analyze_javascript_endpoints(
    js_urls: list[str],
    endpoint_urls: list[str],
    asset_summaries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    hosts = [urlparse(url).hostname or url for url in js_urls + endpoint_urls]
    fallback = _ai_scan_fallback([host for host in hosts if host], "javascript")
    if asset_summaries:
        for asset in asset_summaries:
            if asset.get("secret_count"):
                fallback["potential_leaks"].append(
                    {
                        "type": "javascript_secret",
                        "detail": asset["url"],
                        "severity": "high",
                    }
                )
    fallback = _validate_ai_scan_response(fallback)
    if not (js_urls or endpoint_urls) or not _is_ai_enabled("scan") or not _check_rate_limit():
        return fallback
    prompt = json.dumps(
        {
            "task": "javascript_analysis",
            "js_urls": js_urls,
            "endpoint_urls": endpoint_urls,
            "asset_summaries": asset_summaries or [],
        }
    )
    try:
        output = await _get_model_response(prompt, task="js", role="js_reader")
        return _validate_ai_scan_response(_parse_json_payload(output))
    except Exception:
        logger.warning("Falling back to local JavaScript endpoint analysis", exc_info=True)
        return fallback


async def analyze_nuclei_findings(nuclei_output: str) -> dict[str, Any]:
    high_value_targets = []
    potential_leaks = []
    for line in (nuclei_output or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pieces = [part.strip() for part in stripped.split(" - ") if part.strip()]
        if len(pieces) >= 2:
            high_value_targets.append(
                {
                    "url": pieces[0],
                    "reason": pieces[-1],
                    "priority": 8 if "critical" in stripped.lower() else 6,
                    "classification": "finding",
                    "source": "nuclei",
                }
            )
        if "token" in stripped.lower() or "secret" in stripped.lower():
            potential_leaks.append({"type": "nuclei", "detail": stripped, "severity": "high"})
    fallback = _validate_ai_scan_response(
        {
            "high_value_targets": high_value_targets,
            "potential_leaks": potential_leaks,
            "suggested_nuclei_templates": ["takeovers/detect-all-takeovers.yaml"],
            "confidence_score": "medium",
            "total_processed": len((nuclei_output or "").splitlines()),
            "batches_processed": 1 if nuclei_output else 0,
        }
    )
    if not nuclei_output or not _is_ai_enabled("analyze") or not _check_rate_limit():
        return fallback
    prompt = json.dumps({"task": "nuclei_findings", "raw_output": nuclei_output[: settings.ai_max_input_chars]})
    try:
        output = await _get_model_response(prompt, task="chain", role="chain_reasoner")
        return _validate_ai_scan_response(_parse_json_payload(output))
    except Exception:
        logger.warning("Falling back to local nuclei analysis", exc_info=True)
        return fallback


async def analyze_scan_data(scan_id: str, target: str, task: str = "scan") -> dict[str, Any]:
    summary = {
        "scan_id": scan_id,
        "target": target,
        "task": task,
        "status": "analyzed",
    }
    if not _is_ai_enabled(task) or not _check_rate_limit():
        return summary
    try:
        output = await _get_model_response(
            prompt=json.dumps(summary),
            system_instruction=ORCHESTRATOR_SYSTEM_PROMPT,
            task=task,
        )
        parsed = _parse_json_payload(output)
        if isinstance(parsed, dict):
            return summary | parsed
    except Exception:
        logger.warning("Falling back to local scan summary", exc_info=True)
    return summary


def _fallback_cvss(vulnerability_type: str, severity: str | None = None) -> dict[str, Any]:
    normalized = (severity or vulnerability_type or "medium").lower()
    mapping = {
        "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "high": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"),
        "medium": (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"),
        "low": (3.7, "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
        "idor": (8.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
        "xss": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        "sqli": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "ssrf": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L"),
        "takeover": (8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    }
    score, vector = mapping.get(normalized, mapping.get(vulnerability_type.lower(), mapping["medium"]))
    label = "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
    return {
        "score": score,
        "vector": vector,
        "label": label,
        "justification": f"Estimated severity for {vulnerability_type or normalized}.",
    }


def rate_finding_severity(finding: dict[str, Any]) -> dict[str, Any]:
    vulnerability_type = str(finding.get("type") or finding.get("template_id") or "finding")
    severity = finding.get("severity")
    return _fallback_cvss(vulnerability_type, severity)


async def generate_payloads(vuln_type: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    from app.services.payload_generator import PayloadGenerator

    payloads = PayloadGenerator.get_payloads_for_type(vuln_type)
    enriched = [
        {
            "payload": payload,
            "rank": index + 1,
            "bypass_probability": round(max(0.15, 1 - (index * 0.08)), 2),
        }
        for index, payload in enumerate(payloads[:10])
    ]
    result = {"vuln_type": vuln_type, "payloads": enriched, "context": context or {}}
    if vuln_type.lower() in ("sqli", "sql_injection"):
        base = context.get("endpoint") if isinstance(context, dict) else None
        result["sqlmap_command"] = f"sqlmap -u \"{base or 'https://target.example/path?id=1'}\" --batch"
    return result


async def analyze_js_content(js_content: str, source_url: str | None = None) -> dict[str, Any]:
    from app.services.intelligence import extract_endpoints_from_javascript, extract_secret_like_strings

    hostname = urlparse(source_url).hostname if source_url else None
    scope = {hostname} if hostname else set()
    endpoints = extract_endpoints_from_javascript(js_content or "", source_url or "https://example.invalid/app.js", scope)
    secrets = extract_secret_like_strings(js_content or "")
    internal_urls = [endpoint for endpoint in endpoints if hostname and hostname in endpoint]
    auth_logic = bool(re.search(r"\b(auth|login|token|jwt|session|oauth|mfa)\b", js_content or "", re.IGNORECASE))
    return {
        "source_url": source_url,
        "endpoints_found": endpoints,
        "secrets_found": secrets,
        "internal_urls": internal_urls,
        "auth_logic": auth_logic,
        "escalate_immediately": bool(secrets),
    }


def analyze_finding_chains(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_endpoint: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        endpoint = str(finding.get("endpoint") or finding.get("matched_url") or finding.get("host") or "").strip()
        if not endpoint:
            continue
        by_endpoint.setdefault(endpoint, []).append(finding)

    chains = []
    for endpoint, grouped in by_endpoint.items():
        if len(grouped) < 2:
            continue
        severities = [str(item.get("severity") or "medium").lower() for item in grouped]
        combined = "Critical" if "critical" in severities else "High" if "high" in severities else "Medium"
        chains.append(
            {
                "endpoint": endpoint,
                "combined_severity": combined,
                "finding_ids": [item.get("id") for item in grouped],
                "narrative": f"Multiple findings intersect on {endpoint}, increasing exploitation leverage.",
            }
        )
    return {"chains": chains}


def estimate_bounty_potential(severity: str) -> str:
    mapping = {
        "critical": "$5,000-$15,000",
        "high": "$1,500-$5,000",
        "medium": "$300-$1,500",
        "low": "$50-$300",
    }
    return mapping.get((severity or "").lower(), "$0-$100")


def _should_generate_report(severity: str, existing_reports: int) -> bool:
    return _is_ai_enabled("report") and (severity or "").lower() in {"high", "critical"} and existing_reports < 10


def _fallback_report(vulnerability: dict[str, Any], severity: str) -> dict[str, Any]:
    cvss = _fallback_cvss(str(vulnerability.get("type") or vulnerability.get("template_id") or "finding"), severity)
    endpoint = vulnerability.get("matched_url") or vulnerability.get("endpoint") or vulnerability.get("host") or "N/A"
    vuln_type = vulnerability.get("type") or vulnerability.get("template_id") or "Finding"
    return {
        "title": f"{vuln_type} on {endpoint}",
        "summary": f"{vuln_type} was identified on {endpoint}.",
        "severity": severity,
        "confidence_score": "medium",
        "cwe_mapping": "[]",
        "owasp_mapping": "[]",
        "cvss_score": str(cvss["score"]),
        "technical_details": vulnerability.get("description") or "Manual validation recommended.",
        "proof_of_concept": "\n".join(vulnerability.get("reproduction_steps") or []) or "Review raw request and replay safely.",
        "exploit_draft": vulnerability.get("payload_used") or "",
        "business_impact": vulnerability.get("impact") or "Potential unauthorized access or data exposure.",
        "bounty_estimate": estimate_bounty_potential(severity),
        "remediation_steps": vulnerability.get("remediation") or "Validate authorization, input handling, and exposure controls.",
        "ai_model_version": MODEL_MAP["deep_analyst"] if severity.lower() in {"high", "critical"} else MODEL_MAP["fast_analyst"],
        "processing_time_ms": 0,
        "data_sent_hash": hashlib.sha256(json.dumps(vulnerability, sort_keys=True, default=str).encode("utf-8")).hexdigest(),
    }


async def generate_elite_vulnerability_report(vulnerability: dict[str, Any]) -> dict[str, Any]:
    severity = str(vulnerability.get("severity") or "medium").lower()
    fallback = _fallback_report(vulnerability, severity)
    if not _is_ai_enabled("report") or not _check_rate_limit():
        return fallback
    role = "deep_analyst" if severity in {"high", "critical"} else "fast_analyst"
    prompt = json.dumps(
        {
            "task": "write_bug_bounty_report",
            "finding": vulnerability,
            "required_fields": list(fallback.keys()),
        },
        default=str,
    )
    try:
        output = await _get_model_response(prompt, task="report", role=role)
        parsed = _parse_json_payload(output)
        if isinstance(parsed, dict):
            merged = fallback | parsed
            merged["data_sent_hash"] = fallback["data_sent_hash"]
            merged["processing_time_ms"] = int(parsed.get("processing_time_ms") or fallback["processing_time_ms"])
            merged["bounty_estimate"] = merged.get("bounty_estimate") or fallback["bounty_estimate"]
            return merged
    except Exception:
        logger.warning("Falling back to local vulnerability report generation", exc_info=True)
    return fallback


async def write_finding_report(finding: dict[str, Any], severity: str | None = None) -> dict[str, Any]:
    payload = dict(finding)
    if severity:
        payload["severity"] = severity.lower()
    report = await generate_elite_vulnerability_report(payload)
    return {"report": report}


async def generate_exploit_draft(vulnerability: dict[str, Any]) -> dict[str, Any]:
    report = await generate_elite_vulnerability_report(vulnerability)
    if "error" in report:
        return {"error": report["error"]}
    return {"exploit_draft": report.get("exploit_draft") or report.get("proof_of_concept") or ""}


def get_model_status_snapshot() -> dict[str, Any]:
    results = _MODEL_STATUS_CACHE.get("results") or {}
    statuses = {
        role: {
            "model": model_id,
            "status": results.get(role, {}).get("status", "PENDING"),
            "response": results.get(role, {}).get("response"),
            "error": results.get(role, {}).get("error"),
            "last_verified_at": results.get(role, {}).get("last_verified_at"),
            "calls_made": results.get(role, {}).get("calls_made", 0),
        }
        for role, model_id in MODEL_MAP.items()
    }
    return {
        "provider": "OpenRouter" if settings.openrouter_key else "Gemini",
        "models": MODEL_MAP,
        "statuses": statuses,
        "updated_at": _MODEL_STATUS_CACHE.get("updated_at"),
    }


async def verify_all_models() -> dict[str, Any]:
    prompt = "Reply with your model name and the word ONLINE only."
    _emit_agent_event(
        {
            "event": "verification_started",
            "timestamp": _utc_now(),
            "task": "verify_all_models",
            "status": "started",
            "success": True,
        }
    )
    results: dict[str, Any] = {}
    cache = _MODEL_STATUS_CACHE.setdefault("results", {})
    for role, model_id in MODEL_MAP.items():
        try:
            response = await call_model(role, prompt, task="verify_model")
            result = {
                "model": model_id,
                "status": "ONLINE",
                "response": response["output"][:80],
                "last_verified_at": _utc_now(),
                "calls_made": int(cache.get(role, {}).get("calls_made", 0)) + 1,
            }
            logger.info("[OK]   %s -> %s", role, model_id)
        except Exception as exc:
            result = {
                "model": model_id,
                "status": "ERROR",
                "error": str(exc),
                "last_verified_at": _utc_now(),
                "calls_made": int(cache.get(role, {}).get("calls_made", 0)) + 1,
            }
            logger.error("[FAIL] %s -> %s", role, exc)
        cache[role] = result
        results[role] = result
    _MODEL_STATUS_CACHE["updated_at"] = _utc_now()
    _emit_agent_event(
        {
            "event": "verification_completed",
            "timestamp": _utc_now(),
            "task": "verify_all_models",
            "status": "completed",
            "success": True,
        }
    )
    return results
