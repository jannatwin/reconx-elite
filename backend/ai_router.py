import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ConsensusResult:
    """Result of consensus analysis between two models"""

    primary_model: str
    secondary_model: str
    primary_confidence: float
    secondary_confidence: float
    consensus_score: float
    agreement: bool
    flaws_detected: List[str]
    final_determination: str
    reasoning: str


@dataclass
class DebateModeConfig:
    """Configuration for debate mode analysis"""

    enable_debate_mode: bool = True
    severity_threshold: str = "P2"  # Trigger debate for P1 and P2
    consensus_threshold: float = 0.7  # Minimum consensus score
    max_debate_attempts: int = 3
    timeout_seconds: int = 60


# Enhanced model routing for Agentic Multi-Model Architecture
MODEL_ROUTING_MAP = {
    # GEMINI 3 FLASH: High-volume data parsing (Nmap/HTTP logs)
    "gemini_3_flash": {
        "model": "google/gemini-3-flash",
        "provider": "gemini",
        "specialties": ["data_parsing", "log_analysis", "pattern_recognition"],
        "max_tokens": 4096,
        "temperature": 0.1,
    },
    # QWEN3 CODER 480B: Business Logic & PoC Generation
    "qwen3_coder_480b": {
        "model": "qwen/qwen3-coder-480b-a35b",
        "provider": "openrouter",
        "specialties": ["business_logic", "poc_generation", "code_analysis"],
        "max_tokens": 8192,
        "temperature": 0.2,
    },
    # LLAMA 3.3 70B: Payload mutation & WAF bypass
    "llama_3_3_70b": {
        "model": "meta-llama/llama-3.3-70b-instruct",
        "provider": "openrouter",
        "specialties": ["payload_mutation", "waf_bypass", "vulnerability_analysis"],
        "max_tokens": 6144,
        "temperature": 0.3,
    },
    # Legacy model mappings for backward compatibility
    "orchestrator": "meta-llama/llama-3.3-70b-instruct",
    "primary_analyst": "meta-llama/llama-3.3-70b-instruct",
    "deep_analyst": "qwen/qwen3-coder-480b-a35b",
    "fast_analyst": "google/gemma-2-9b-it:free",
    "chain_reasoner": "nvidia/nemotron-3-8b-instruct",
    "code_engine": "qwen/qwen3-coder-480b-a35b",
    "js_reader": "minimax/minimax-m1-5:free",
    "fast_classifier": "google/gemma-2-9b-it:free",
    "structured_output": "google/gemma-2-9b-it:free",
    "misconfig_analyst": "meta-llama/llama-3.3-70b-instruct",
}

# Task-to-model routing configuration
TASK_ROUTING = {
    "data_parsing": "gemini_3_flash",
    "log_analysis": "gemini_3_flash",
    "pattern_recognition": "gemini_3_flash",
    "business_logic": "qwen3_coder_480b",
    "poc_generation": "qwen3_coder_480b",
    "code_analysis": "qwen3_coder_480b",
    "payload_mutation": "llama_3_3_70b",
    "waf_bypass": "llama_3_3_70b",
    "vulnerability_analysis": "llama_3_3_70b",
}


class AIRouter:
    """Enhanced AI Router with task-specific model selection and fallback logic"""

    def __init__(self) -> None:
        self.openrouter_key = os.getenv("OPENROUTER_KEY", "").strip()
        self.gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

        # Initialize API endpoints
        self.openrouter_url = "https://openrouter.ai/api/v1/chat/completions"
        self.gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash:generateContent"

        # Model availability tracking
        self.model_availability = self._check_model_availability()

        if not self.openrouter_key and not self.gemini_key:
            logger.warning(
                "No AI API keys configured. AI calls will return fallback responses."
            )

    def _check_model_availability(self) -> dict[str, bool]:
        """Check which models are available based on API keys"""
        availability = {
            "openrouter": bool(self.openrouter_key),
            "gemini": bool(self.gemini_key),
        }
        return availability

    def _select_model_for_task(
        self, task_type: str, fallback_role: str = "orchestrator"
    ) -> dict[str, Any]:
        """Select the best model for a specific task type"""
        # Try task-specific routing first
        if task_type in TASK_ROUTING:
            model_key = TASK_ROUTING[task_type]
            if model_key in MODEL_ROUTING_MAP:
                model_config = MODEL_ROUTING_MAP[model_key]

                # Check if the model's provider is available
                provider = model_config["provider"]
                if self.model_availability.get(provider, False):
                    return {
                        "model_id": model_config["model"],
                        "provider": provider,
                        "max_tokens": model_config["max_tokens"],
                        "temperature": model_config["temperature"],
                        "url": (
                            self.gemini_url
                            if provider == "gemini"
                            else self.openrouter_url
                        ),
                    }

        # Fallback to legacy model mapping
        legacy_model_map = {
            "orchestrator": "meta-llama/llama-3.3-70b-instruct",
            "primary_analyst": "meta-llama/llama-3.3-70b-instruct",
            "deep_analyst": "qwen/qwen3-coder-480b-a35b",
            "fast_analyst": "google/gemma-2-9b-it:free",
            "chain_reasoner": "nvidia/nemotron-3-8b-instruct",
            "code_engine": "qwen/qwen3-coder-480b-a35b",
            "js_reader": "minimax/minimax-m1-5:free",
            "fast_classifier": "google/gemma-2-9b-it:free",
            "structured_output": "google/gemma-2-9b-it:free",
            "misconfig_analyst": "meta-llama/llama-3.3-70b-instruct",
        }

        if fallback_role in legacy_model_map:
            if self.model_availability["openrouter"]:
                return {
                    "model_id": legacy_model_map[fallback_role],
                    "provider": "openrouter",
                    "max_tokens": 2048,
                    "temperature": 0.2,
                    "url": self.openrouter_url,
                }

        # Final fallback
        return {
            "model_id": legacy_model_map.get(
                "orchestrator", "meta-llama/llama-3.3-70b-instruct"
            ),
            "provider": "openrouter",
            "max_tokens": 2048,
            "temperature": 0.2,
            "url": self.openrouter_url,
        }

    async def call_model(
        self,
        role: str,
        prompt: str,
        max_tokens: int = 2048,
        retries: int = 3,
        task_type: str = None,
    ) -> dict[str, Any]:
        """Enhanced model calling with task-specific routing"""

        # Select model based on task type or role
        model_config = self._select_model_for_task(task_type or role, role)

        # Check API availability
        if model_config["provider"] == "openrouter" and not self.openrouter_key:
            return {
                "role": role,
                "model": model_config["model_id"],
                "output": "",
                "error": "missing_openrouter_key",
            }

        if model_config["provider"] == "gemini" and not self.gemini_key:
            return {
                "role": role,
                "model": model_config["model_id"],
                "output": "",
                "error": "missing_gemini_key",
            }

        # Prepare payload based on provider
        if model_config["provider"] == "gemini":
            payload = self._prepare_gemini_payload(
                prompt, max_tokens, model_config["temperature"]
            )
            headers = self._prepare_gemini_headers()
        else:
            payload = self._prepare_openrouter_payload(
                prompt,
                max_tokens,
                model_config["temperature"],
                model_config["model_id"],
            )
            headers = self._prepare_openrouter_headers()

        # Execute with retry logic
        last_error: str | None = None
        delay = 1.0

        for attempt in range(1, retries + 1):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        model_config["url"],
                        headers=headers,
                        json=payload,
                    )
                    response.raise_for_status()
                    result = response.json()

                # Extract content based on provider
                if model_config["provider"] == "gemini":
                    content = self._extract_gemini_content(result)
                else:
                    content = (
                        result.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", "")
                    )

                return {
                    "role": role,
                    "model": model_config["model_id"],
                    "provider": model_config["provider"],
                    "output": content,
                    "task_type": task_type,
                }

            except Exception as exc:
                last_error = str(exc)
                logger.warning(
                    "AI model call failed (attempt %s/%s): %s", attempt, retries, exc
                )
                await asyncio.sleep(delay)
                delay *= 2

        return {
            "role": role,
            "model": model_config["model_id"],
            "provider": model_config["provider"],
            "output": "",
            "error": "model_call_failed",
            "details": last_error,
            "task_type": task_type,
        }

    def _prepare_gemini_payload(
        self, prompt: str, max_tokens: int, temperature: float
    ) -> dict[str, Any]:
        """Prepare payload for Gemini API"""
        return {
            "contents": [
                {"parts": [{"text": f"You are a security AI assistant.\n\n{prompt}"}]}
            ],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }

    def _prepare_openrouter_payload(
        self, prompt: str, max_tokens: int, temperature: float, model_id: str
    ) -> dict[str, Any]:
        """Prepare payload for OpenRouter API"""
        return {
            "model": model_id,
            "messages": [
                {"role": "system", "content": "You are a security AI assistant."},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

    def _prepare_gemini_headers(self) -> dict[str, str]:
        """Prepare headers for Gemini API"""
        return {"Content-Type": "application/json", "x-goog-api-key": self.gemini_key}

    def _prepare_openrouter_headers(self) -> dict[str, str]:
        """Prepare headers for OpenRouter API"""
        return {
            "Authorization": f"Bearer {self.openrouter_key}",
            "Content-Type": "application/json",
        }

    def _extract_gemini_content(self, result: dict[str, Any]) -> str:
        """Extract content from Gemini API response"""
        try:
            candidates = result.get("candidates", [])
            if candidates and candidates[0].get("content"):
                parts = candidates[0]["content"].get("parts", [])
                if parts and parts[0].get("text"):
                    return parts[0]["text"]
        except (KeyError, IndexError, TypeError):
            pass
        return ""

    async def classify_hosts(
        self, hosts_list: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if not hosts_list:
            return []
        results = []
        for host in hosts_list:
            name = host.get("url") or host.get("host") or ""
            category = (
                "api_target"
                if "/api" in name or "api." in name
                else (
                    "auth_target"
                    if "login" in name or "admin" in name
                    else (
                        "dev_target"
                        if "dev" in name
                        else "admin_target" if "admin" in name else "skip"
                    )
                )
            )
            results.append({**host, "category": category})
        return results

    async def analyze_js_content(self, content: str) -> dict[str, Any]:
        endpoints = []
        secrets = []
        auth_logic = ""
        for line in content.splitlines():
            if "fetch(" in line or "axios." in line or ".post(" in line:
                if "(" in line:
                    endpoints.append(line.strip())
            if "apiKey" in line or "secret" in line or "token" in line:
                secrets.append(line.strip())
        return {"endpoints": endpoints, "secrets": secrets, "auth_logic": auth_logic}

    async def generate_idor_tests(
        self, endpoint: str, method: str, params: list[str]
    ) -> list[dict[str, Any]]:
        tests = []
        for param in params[:3]:
            tests.append(
                {
                    "endpoint": endpoint,
                    "method": method,
                    "payload": {param: "1"},
                    "expected": "403 or record owner check",
                }
            )
        return tests

    async def analyze_jwt(self, token: str) -> dict[str, Any]:
        if not token:
            return {"vectors": [], "summary": "No token provided"}
        return {
            "vectors": ["alg none injection", "kid header manipulation"],
            "summary": "Check token signing algorithm and header trust.",
        }

    async def analyze_headers(
        self, headers_dict: dict[str, str], target: str
    ) -> list[dict[str, Any]]:
        findings = []
        if headers_dict.get("access-control-allow-origin") in (
            "*",
            "https://evil-reconx.com",
        ):
            findings.append(
                {"issue": "CORS policy too permissive", "severity": "Medium"}
            )
        if "x-frame-options" not in headers_dict:
            findings.append(
                {"issue": "Missing X-Frame-Options header", "severity": "Low"}
            )
        if "content-security-policy" not in headers_dict:
            findings.append(
                {
                    "issue": "Missing Content-Security-Policy header",
                    "severity": "Medium",
                }
            )
        return findings

    async def rate_severity(self, finding_dict: dict[str, Any]) -> dict[str, Any]:
        severity = finding_dict.get("severity", "Low")
        if severity.lower() == "critical":
            return {
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        if severity.lower() == "high":
            return {
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            }
        if severity.lower() == "medium":
            return {
                "cvss_score": 5.4,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            }
        return {
            "cvss_score": 3.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        }

    async def find_chains(
        self, findings_list: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if len(findings_list) < 2:
            return []
        return [
            {
                "chain_id": 1,
                "findings": [f.get("id") for f in findings_list],
                "severity": "High",
                "description": "Potential attack chain connecting multiple findings.",
            }
        ]

    async def write_report(self, finding_dict: dict[str, Any]) -> str:
        return f"Finding report for {finding_dict.get('vuln_type')} at {finding_dict.get('endpoint')}: {finding_dict.get('description')}"

    async def analyze_target_recon(
        self, target: str, discovered_info: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "priority_targets": [target],
            "attack_plan": "Focus on live hosts, API endpoints, and exposed metadata.",
        }

    async def generate_executive_summary(
        self, all_findings: list[dict[str, Any]], stats: dict[str, Any]
    ) -> str:
        critical = sum(1 for f in all_findings if f.get("severity") == "Critical")
        high = sum(1 for f in all_findings if f.get("severity") == "High")
        return f"ReconX-Elite scanned {stats.get('total_subdomains', 0)} subdomains and found {critical} critical and {high} high issues. Review the findings for remediation guidance."

    async def consensus_debate_mode(
        self,
        vulnerability_data: Dict[str, Any],
        severity: str,
        config: Optional[DebateModeConfig] = None,
    ) -> ConsensusResult:
        """Execute consensus debate mode between Qwen3 Coder and Llama 3.3 for critical findings"""
        if not config:
            config = DebateModeConfig()

        # Check if debate mode should be triggered
        if not config.enable_debate_mode:
            return ConsensusResult(
                primary_model="qwen3_coder_480b",
                secondary_model="llama_3_3_70b",
                primary_confidence=0.5,
                secondary_confidence=0.5,
                consensus_score=0.5,
                agreement=True,
                flaws_detected=[],
                final_determination="pass",
                reasoning="Debate mode disabled",
            )

        # Check severity threshold
        if severity not in ["P1", "P2", "critical", "high"]:
            return ConsensusResult(
                primary_model="qwen3_coder_480b",
                secondary_model="llama_3_3_70b",
                primary_confidence=0.5,
                secondary_confidence=0.5,
                consensus_score=0.5,
                agreement=True,
                flaws_detected=[],
                final_determination="pass",
                reasoning=f"Severity {severity} below threshold {config.severity_threshold}",
            )

        try:
            # Phase 1: Primary model analysis (Qwen3 Coder)
            primary_result = await self._primary_model_analysis(vulnerability_data)

            # Phase 2: Secondary model review (Llama 3.3)
            secondary_result = await self._secondary_model_review(
                vulnerability_data, primary_result
            )

            # Phase 3: Consensus calculation
            consensus_result = await self._calculate_consensus(
                primary_result, secondary_result, config
            )

            return consensus_result

        except Exception as e:
            logger.error(f"Consensus debate mode failed: {e}")
            return ConsensusResult(
                primary_model="qwen3_coder_480b",
                secondary_model="llama_3_3_70b",
                primary_confidence=0.0,
                secondary_confidence=0.0,
                consensus_score=0.0,
                agreement=False,
                flaws_detected=[f"Debate mode error: {str(e)}"],
                final_determination="fail",
                reasoning="Consensus analysis failed due to error",
            )

    async def _primary_model_analysis(
        self, vulnerability_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Primary model analysis using Qwen3 Coder 480B"""
        prompt = f"""
        Analyze this vulnerability finding and provide your expert assessment:
        
        Vulnerability Data:
        {json.dumps(vulnerability_data, indent=2)}
        
        Provide:
        1. Confidence score (0.0-1.0)
        2. Severity assessment
        3. Exploit logic validation
        4. Potential false positive indicators
        5. Recommended action
        
        Return as JSON: {{"confidence": 0.9, "severity": "critical", "exploit_logic": "valid", "false_positive_indicators": [], "recommended_action": "immediate"}}
        """

        analysis_error = None
        try:
            result = await self.call_model(
                role="code_engine",  # Qwen3 Coder 480B
                prompt=prompt,
                max_tokens=800,
                task_type="vulnerability_analysis",
            )

            if result.get("output"):
                try:
                    analysis = json.loads(result["output"])
                    return {
                        "model": result["model"],
                        "confidence": analysis.get("confidence", 0.5),
                        "severity": analysis.get("severity", "medium"),
                        "exploit_logic": analysis.get("exploit_logic", "unknown"),
                        "false_positive_indicators": analysis.get(
                            "false_positive_indicators", []
                        ),
                        "recommended_action": analysis.get(
                            "recommended_action", "review"
                        ),
                        "raw_output": result["output"],
                    }
                except json.JSONDecodeError:
                    logger.warning("Primary model analysis response not valid JSON")

        except Exception as e:
            analysis_error = str(e)
            logger.error(f"Primary model analysis failed: {e}")

        return {
            "model": "qwen3_coder_480b",
            "confidence": 0.5,
            "severity": "medium",
            "exploit_logic": "unknown",
            "false_positive_indicators": [],
            "recommended_action": "review",
            "raw_output": "",
            "error": analysis_error,
        }

    async def _secondary_model_review(
        self, vulnerability_data: Dict[str, Any], primary_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Secondary model review using Llama 3.3 70B"""
        prompt = f"""
        Review and critique the primary model's analysis of this vulnerability:
        
        Vulnerability Data:
        {json.dumps(vulnerability_data, indent=2)}
        
        Primary Model Analysis:
        {json.dumps(primary_result, indent=2)}
        
        Your task is to:
        1. Validate the primary model's confidence score
        2. Check for logical flaws in the exploit logic
        3. Identify potential false positive indicators
        4. Assess if the severity is appropriate
        5. Provide your own confidence assessment
        
        Look specifically for:
        - Overconfidence or underconfidence
        - Logical inconsistencies
        - Missing context or assumptions
        - Technical inaccuracies
        
        Return as JSON: {{"confidence": 0.8, "flaws_detected": ["flaw1"], "agreement": true, "severity_assessment": "critical", "reasoning": "detailed reasoning"}}
        """

        secondary_error = None
        try:
            result = await self.call_model(
                role="deep_analyst",  # Llama 3.3 70B
                prompt=prompt,
                max_tokens=800,
                task_type="consensus_analysis",
            )

            if result.get("output"):
                try:
                    review = json.loads(result["output"])
                    return {
                        "model": result["model"],
                        "confidence": review.get("confidence", 0.5),
                        "flaws_detected": review.get("flaws_detected", []),
                        "agreement": review.get("agreement", True),
                        "severity_assessment": review.get(
                            "severity_assessment", "medium"
                        ),
                        "reasoning": review.get("reasoning", ""),
                        "raw_output": result["output"],
                    }
                except json.JSONDecodeError:
                    logger.warning("Secondary model review response not valid JSON")

        except Exception as e:
            secondary_error = str(e)
            logger.error(f"Secondary model review failed: {e}")

        return {
            "model": "llama_3_3_70b",
            "confidence": 0.5,
            "flaws_detected": [],
            "agreement": True,
            "severity_assessment": "medium",
            "reasoning": "Review failed due to error",
            "raw_output": "",
            "error": secondary_error,
        }

    async def _calculate_consensus(
        self,
        primary_result: Dict[str, Any],
        secondary_result: Dict[str, Any],
        config: DebateModeConfig,
    ) -> ConsensusResult:
        """Calculate consensus between primary and secondary model results"""
        primary_confidence = primary_result.get("confidence", 0.5)
        secondary_confidence = secondary_result.get("confidence", 0.5)

        # Calculate consensus score
        if secondary_result.get("agreement", True):
            consensus_score = (primary_confidence + secondary_confidence) / 2.0
        else:
            consensus_score = abs(primary_confidence - secondary_confidence) / 2.0

        # Determine final determination
        flaws_detected = secondary_result.get("flaws_detected", [])
        has_critical_flaws = any(
            "critical" in flaw.lower() or "major" in flaw.lower()
            for flaw in flaws_detected
        )

        if consensus_score >= config.consensus_threshold and not has_critical_flaws:
            final_determination = "pass"
        elif consensus_score < config.consensus_threshold or has_critical_flaws:
            final_determination = "fail"
        else:
            final_determination = "review"

        # Generate reasoning
        reasoning = f"Primary model confidence: {primary_confidence:.2f}, Secondary model confidence: {secondary_confidence:.2f}"
        if flaws_detected:
            reasoning += f", Flaws detected: {', '.join(flaws_detected)}"
        if not secondary_result.get("agreement", True):
            reasoning += ", Models disagree on assessment"

        return ConsensusResult(
            primary_model=primary_result.get("model", "qwen3_coder_480b"),
            secondary_model=secondary_result.get("model", "llama_3_3_70b"),
            primary_confidence=primary_confidence,
            secondary_confidence=secondary_confidence,
            consensus_score=consensus_score,
            agreement=secondary_result.get("agreement", True),
            flaws_detected=flaws_detected,
            final_determination=final_determination,
            reasoning=reasoning,
        )
