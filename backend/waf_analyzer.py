"""
WAF Analyzer - Phase 8 of Agentic Multi-Model Vulnerability Research Engine
Implements WAF fingerprinting and stealth configuration for evasive scanning
"""

import asyncio
import httpx
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ai_router import AIRouter
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


class WAFType(Enum):
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    AWS_WAF = "aws_waf"
    AZURE_WAF = "azure_waf"
    MODSECURITY = "modsecurity"
    F5_ASM = "f5_asm"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    SQUID = "squid"
    NGINX = "nginx"
    UNKNOWN = "unknown"


@dataclass
class WAFSignature:
    signature_type: str
    pattern: str
    response_indicator: str
    confidence: float


@dataclass
class WAFProfile:
    waf_type: WAFType
    confidence: float
    signatures: List[WAFSignature]
    rate_limit_detected: bool
    rate_limit_threshold: Optional[int]
    recommended_delay: float
    stealth_mode: bool
    evasion_techniques: List[str]


class WAFAnalyzer:
    """WAF fingerprinting and stealth configuration system"""

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager

        # Storage for results
        self.waf_profile: Optional[WAFProfile] = None
        self.stealth_config: Dict[str, Any] = {}

        # Proxy rotation configuration
        self.proxy_config = {
            "enabled": False,
            "providers": [],
            "current_provider_index": 0,
            "rotation_count": 0,
            "rotation_threshold": 3,  # Rotate after 3 failures
            "bypass_failure_count": 0,
        }

        # Proxy provider configurations
        self.proxy_providers = {
            "bright_data": {
                "api_url": "https://api.brightdata.com/zone",
                "auth_header": "Token",
                "supports_rotation": True,
            },
            "oxylabs": {
                "api_url": "https://api.oxylabs.io/v1",
                "auth_header": "Authorization",
                "supports_rotation": True,
            },
            "smartproxy": {
                "api_url": "https://api.smartproxy.com/v1",
                "auth_header": "Authorization",
                "supports_rotation": True,
            },
            "custom": {
                "api_url": os.getenv("CUSTOM_PROXY_API_URL", ""),
                "auth_header": "Authorization",
                "supports_rotation": True,
            },
        }

        # WAF signature patterns
        self.waf_signatures = {
            WAFType.CLOUDFLARE: [
                WAFSignature(
                    "server_header", r"cloudflare", "Cloudflare server header", 0.9
                ),
                WAFSignature("error_page", r"cloudflare", "Cloudflare error page", 0.8),
                WAFSignature("ray_id", r"ray_id|cf-ray", "Cloudflare Ray ID", 0.9),
                WAFSignature(
                    "response_code", r"403.*cloudflare", "Cloudflare 403 page", 0.7
                ),
            ],
            WAFType.AKAMAI: [
                WAFSignature("server_header", r"akamai", "Akamai server header", 0.9),
                WAFSignature("error_page", r"akamai", "Akamai error page", 0.8),
                WAFSignature("cookies", r"akamai", "Akamai cookies", 0.7),
                WAFSignature("headers", r"akamai", "Akamai custom headers", 0.6),
            ],
            WAFType.IMPERVA: [
                WAFSignature("server_header", r"incapsula", "Imperva Incapsula", 0.9),
                WAFSignature("error_page", r"incapsula", "Imperva error page", 0.8),
                WAFSignature("cookies", r"incapsula", "Imperva cookies", 0.7),
                WAFSignature("headers", r"x-incapula", "Imperva headers", 0.8),
            ],
            WAFType.AWS_WAF: [
                WAFSignature("error_page", r"aws.*waf", "AWS WAF error page", 0.7),
                WAFSignature("headers", r"x-amzn-waf", "AWS WAF headers", 0.9),
                WAFSignature("response_code", r"403.*blocked", "AWS WAF block", 0.6),
                WAFSignature("cookies", r"aws.*waf", "AWS WAF cookies", 0.5),
            ],
            WAFType.MODSECURITY: [
                WAFSignature(
                    "error_page", r"modsecurity", "ModSecurity error page", 0.8
                ),
                WAFSignature("headers", r"x-modsecurity", "ModSecurity headers", 0.9),
                WAFSignature(
                    "server_header", r"modsecurity", "ModSecurity server", 0.6
                ),
                WAFSignature(
                    "response_code", r"403.*modsecurity", "ModSecurity block", 0.7
                ),
            ],
            WAFType.F5_ASM: [
                WAFSignature("server_header", r"big-ip|f5", "F5 Big-IP header", 0.8),
                WAFSignature("error_page", r"f5.*asm", "F5 ASM error page", 0.7),
                WAFSignature("cookies", r"bigip", "F5 cookies", 0.6),
                WAFSignature("headers", r"x-f5", "F5 headers", 0.7),
            ],
            WAFType.NGINX: [
                WAFSignature("server_header", r"nginx", "Nginx server header", 0.5),
                WAFSignature("error_page", r"nginx", "Nginx error page", 0.4),
                WAFSignature("headers", r"x-nginx", "Nginx headers", 0.6),
            ],
        }

        # Test payloads for WAF detection
        self.waf_test_payloads = [
            {"path": "/test", "params": {"id": "1' OR '1'='1"}},  # SQL injection
            {"path": "/test", "params": {"q": "<script>alert(1)</script>"}},  # XSS
            {"path": "/test", "params": {"file": "/etc/passwd"}},  # LFI
            {"path": "/test", "params": {"url": "http://evil.com"}},  # SSRF
            {"path": "/test", "params": {"cmd": "whoami"}},  # Command injection
            {
                "path": "/test",
                "params": {"test": "../../../etc/passwd"},
            },  # Path traversal
        ]

    async def execute(self) -> Dict[str, Any]:
        """Execute WAF analysis and stealth configuration"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting WAF analysis and stealth configuration...",
            phase="waf_analysis",
        )

        try:
            # Phase 8.0: Initialize Proxy Configuration
            await self._initialize_proxy_configuration()

            # Phase 8.1: WAF Fingerprinting
            await self._fingerprint_waf()

            # Phase 8.2: Rate Limiting Detection
            await self._detect_rate_limiting()

            # Phase 8.3: AI-Recommended Delay Calculation
            await self._calculate_recommended_delay()

            # Phase 8.4: Evasion Techniques Analysis
            await self._analyze_evasion_techniques()

            # Phase 8.5: Stealth Configuration
            await self._configure_stealth_mode()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f'WAF analysis completed: {self.waf_profile.waf_type.value if self.waf_profile else "unknown"} detected, '
                f'recommended delay: {self.stealth_config.get("recommended_delay", 0.0)}s',
                phase="waf_analysis",
            )

            return results

        except Exception as e:
            logger.error(f"WAF analysis failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"WAF analysis failed: {str(e)}",
                phase="waf_analysis",
            )
            raise

    async def _fingerprint_waf(self) -> None:
        """Fingerprint WAF type and configuration"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Fingerprinting WAF...", phase="waf_analysis"
        )

        # Test base target
        base_url = f"https://{self.target}"

        # Analyze base response
        base_response = await self._analyze_response(base_url)

        # Test with WAF-triggering payloads
        payload_responses = []
        for payload in self.waf_test_payloads[:3]:  # Limit to prevent blocking
            try:
                test_url = f"{base_url}{payload['path']}"
                response = await self._analyze_response(test_url, payload["params"])
                payload_responses.append(response)

                # Add delay to avoid being blocked
                await asyncio.sleep(1)

            except Exception as e:
                logger.debug(f"WAF test payload failed: {e}")

        # Use AI to analyze WAF
        waf_type = await self._ai_detect_waf_type(base_response, payload_responses)

        # Create WAF profile
        await self._create_waf_profile(waf_type, base_response, payload_responses)

    async def _analyze_response(
        self, url: str, params: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Analyze HTTP response for WAF indicators"""
        try:
            if params:
                # Add parameters to URL
                query_string = "&".join([f"{k}={v}" for k, v in params.items()])
                test_url = f"{url}?{query_string}"
            else:
                test_url = url

            result = await self.tool_runner.run_tool(
                "http_request", {"url": test_url, "method": "GET"}
            )

            if result:
                return {
                    "url": test_url,
                    "status_code": result.get("status_code", 0),
                    "headers": result.get("headers", {}),
                    "data": result.get("data", ""),
                    "response_time": result.get("response_time", 0),
                    "params": params or {},
                }

        except Exception as e:
            logger.debug(f"Response analysis failed: {e}")

        return {
            "url": url,
            "status_code": 0,
            "headers": {},
            "data": "",
            "params": params or {},
        }

    async def _ai_detect_waf_type(
        self, base_response: Dict[str, Any], payload_responses: List[Dict[str, Any]]
    ) -> WAFType:
        """Use AI to detect WAF type"""
        # Prepare response data for AI
        response_data = {
            "base_response": {
                "status_code": base_response.get("status_code"),
                "headers": base_response.get("headers", {}),
                "data_sample": base_response.get("data", "")[:500],
            },
            "payload_responses": [],
        }

        for resp in payload_responses:
            response_data["payload_responses"].append(
                {
                    "status_code": resp.get("status_code"),
                    "headers": resp.get("headers", {}),
                    "data_sample": resp.get("data", "")[:300],
                    "params": resp.get("params", {}),
                }
            )

        prompt = f"""
        Analyze the HTTP responses to detect the Web Application Firewall (WAF) type for {self.target}:
        
        Base Response:
        - Status: {response_data['base_response']['status_code']}
        - Headers: {response_data['base_response']['headers']}
        - Data Sample: {response_data['base_response']['data_sample']}
        
        Payload Responses:
        {json.dumps(response_data['payload_responses'], indent=2)}
        
        WAF types to consider:
        - cloudflare: Cloudflare WAF
        - akamai: Akamai WAF
        - impera: Imperva Incapsula
        - aws_waf: AWS WAF
        - azure_waf: Azure WAF
        - modsecurity: ModSecurity
        - f5_asm: F5 ASM
        - barracuda: Barracuda WAF
        - fortinet: Fortinet FortiWeb
        - nginx: Nginx with WAF module
        - unknown: Unknown or no WAF
        
        Look for:
        1. Server headers indicating WAF
        2. Custom WAF headers
        3. WAF-specific error pages
        4. Blocking patterns in responses
        5. Rate limiting indicators
        
        Return as JSON: {{"waf_type": "cloudflare", "confidence": 0.9, "indicators": ["server_header", "error_page"]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",  # Use Gemini 3 Flash for speed
                prompt=prompt,
                max_tokens=400,
                task_type="data_parsing",
            )

            if result.get("output"):
                try:
                    analysis = json.loads(result["output"])
                    waf_type_str = analysis.get("waf_type", "unknown")
                    confidence = analysis.get("confidence", 0.5)

                    # Convert to enum
                    for waf_type in WAFType:
                        if waf_type.value == waf_type_str:
                            return waf_type

                    return WAFType.UNKNOWN

                except json.JSONDecodeError:
                    logger.warning("AI WAF detection response not valid JSON")

        except Exception as e:
            logger.error(f"AI WAF detection failed: {e}")

        return WAFType.UNKNOWN

    async def _create_waf_profile(
        self,
        waf_type: WAFType,
        base_response: Dict[str, Any],
        payload_responses: List[Dict[str, Any]],
    ) -> None:
        """Create WAF profile with detected signatures"""
        signatures = []
        confidence = 0.0

        # Check for WAF-specific signatures
        if waf_type in self.waf_signatures:
            waf_signature_patterns = self.waf_signatures[waf_type]

            for signature_pattern in waf_signature_patterns:
                # Check in base response
                if self._check_signature(signature_pattern, base_response):
                    signatures.append(signature_pattern)
                    confidence += signature_pattern.confidence * 0.3

                # Check in payload responses
                for response in payload_responses:
                    if self._check_signature(signature_pattern, response):
                        signatures.append(signature_pattern)
                        confidence += signature_pattern.confidence * 0.2

        # Normalize confidence
        confidence = min(confidence, 1.0)

        self.waf_profile = WAFProfile(
            waf_type=waf_type,
            confidence=confidence,
            signatures=signatures,
            rate_limit_detected=False,
            rate_limit_threshold=None,
            recommended_delay=0.0,
            stealth_mode=False,
            evasion_techniques=[],
        )

    def _check_signature(
        self, signature: WAFSignature, response: Dict[str, Any]
    ) -> bool:
        """Check if WAF signature matches response"""
        pattern = signature.pattern.lower()

        # Check in headers
        headers_str = str(response.get("headers", {})).lower()
        if re.search(pattern, headers_str):
            return True

        # Check in data
        data_str = response.get("data", "").lower()
        if re.search(pattern, data_str):
            return True

        # Check in status code
        if signature.signature_type == "response_code":
            status_code = str(response.get("status_code", ""))
            if re.search(pattern, status_code.lower()):
                return True

        return False

    async def _detect_rate_limiting(self) -> None:
        """Detect rate limiting thresholds"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Detecting rate limiting...", phase="waf_analysis"
        )

        if not self.waf_profile:
            return

        base_url = f"https://{self.target}"

        # Test rapid requests to detect rate limiting
        test_results = []

        for i in range(10):  # Send 10 rapid requests
            try:
                start_time = time.time()
                response = await self._analyze_response(base_url)
                end_time = time.time()

                test_results.append(
                    {
                        "request_num": i + 1,
                        "status_code": response.get("status_code", 0),
                        "response_time": end_time - start_time,
                        "timestamp": end_time,
                    }
                )

            except Exception as e:
                logger.debug(f"Rate limiting test failed for request {i+1}: {e}")

        # Analyze results for rate limiting
        rate_limit_detected, threshold = self._analyze_rate_limiting_results(
            test_results
        )

        self.waf_profile.rate_limit_detected = rate_limit_detected
        self.waf_profile.rate_limit_threshold = threshold

    def _analyze_rate_limiting_results(
        self, test_results: List[Dict[str, Any]]
    ) -> Tuple[bool, Optional[int]]:
        """Analyze rate limiting test results"""
        if len(test_results) < 5:
            return False, None

        # Check for 429 status codes
        rate_429_count = len([r for r in test_results if r.get("status_code") == 429])

        if rate_429_count > 0:
            return True, 10 - rate_429_count + 1  # Approximate threshold

        # Check for increasing response times
        response_times = [r.get("response_time", 0) for r in test_results]

        if len(response_times) >= 3:
            # Check if response times are increasing significantly
            avg_first_half = sum(response_times[: len(response_times) // 2]) / (
                len(response_times) // 2
            )
            avg_second_half = sum(response_times[len(response_times) // 2 :]) / (
                len(response_times) // 2 + len(response_times) % 2
            )

            if avg_second_half > avg_first_half * 2:
                return True, len(test_results) // 2

        return False, None

    async def _calculate_recommended_delay(self) -> None:
        """Calculate AI-recommended request delay"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Calculating recommended delay...",
            phase="waf_analysis",
        )

        if not self.waf_profile:
            self.stealth_config["recommended_delay"] = 1.0
            return

        # Base delay calculation
        base_delay = 1.0

        # Adjust based on WAF type
        waf_delay_multipliers = {
            WAFType.CLOUDFLARE: 2.0,
            WAFType.AKAMAI: 1.8,
            WAFType.IMPERVA: 1.5,
            WAFType.AWS_WAF: 1.3,
            WAFType.MODSECURITY: 1.2,
            WAFType.F5_ASM: 1.4,
            WAFType.BARRACUDA: 1.3,
            WAFType.FORTINET: 1.2,
            WAFType.NGINX: 1.0,
            WAFType.UNKNOWN: 0.5,
        }

        delay = base_delay * waf_delay_multipliers.get(self.waf_profile.waf_type, 1.0)

        # Adjust based on confidence
        if self.waf_profile.confidence > 0.8:
            delay *= 1.5
        elif self.waf_profile.confidence > 0.6:
            delay *= 1.2

        # Adjust based on rate limiting
        if self.waf_profile.rate_limit_detected:
            if self.waf_profile.rate_limit_threshold:
                delay = max(delay, self.waf_profile.rate_limit_threshold * 0.5)
            else:
                delay *= 2.0

        # Use AI to refine delay calculation
        refined_delay = await self._ai_refine_delay(delay)

        self.waf_profile.recommended_delay = refined_delay
        self.stealth_config["recommended_delay"] = refined_delay

    async def _ai_refine_delay(self, initial_delay: float) -> float:
        """Use AI to refine delay calculation"""
        prompt = f"""
        Refine the recommended request delay for scanning {self.target}.
        
        WAF Analysis:
        - Type: {self.waf_profile.waf_type.value if self.waf_profile else 'unknown'}
        - Confidence: {self.waf_profile.confidence if self.waf_profile else 0.0}
        - Rate Limiting: {self.waf_profile.rate_limit_detected if self.waf_profile else False}
        - Initial Delay: {initial_delay}s
        
        Consider:
        1. WAF sensitivity and blocking patterns
        2. Rate limiting thresholds
        3. Stealth vs. speed trade-offs
        4. Typical scanning patterns
        
        Recommend a delay between 0.5 and 10.0 seconds.
        Return as JSON: {{"refined_delay": 2.5, "reasoning": "High-sensitivity WAF detected"}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",
                prompt=prompt,
                max_tokens=200,
                task_type="pattern_recognition",
            )

            if result.get("output"):
                try:
                    refinement = json.loads(result["output"])
                    refined_delay = refinement.get("refined_delay", initial_delay)

                    # Clamp to reasonable range
                    return max(0.5, min(10.0, refined_delay))

                except json.JSONDecodeError:
                    logger.warning("AI delay refinement response not valid JSON")

        except Exception as e:
            logger.error(f"AI delay refinement failed: {e}")

        return initial_delay

    async def _analyze_evasion_techniques(self) -> None:
        """Analyze effective evasion techniques"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Analyzing evasion techniques...",
            phase="waf_analysis",
        )

        if not self.waf_profile:
            return

        # Get evasion techniques based on WAF type
        evasion_techniques = await self._ai_get_evasion_techniques()

        self.waf_profile.evasion_techniques = evasion_techniques
        self.stealth_config["evasion_techniques"] = evasion_techniques

    async def _ai_get_evasion_techniques(self) -> List[str]:
        """Use AI to get evasion techniques"""
        prompt = f"""
        Recommend effective evasion techniques for {self.waf_profile.waf_type.value} WAF at {self.target}.
        
        WAF Profile:
        - Type: {self.waf_profile.waf_type.value}
        - Confidence: {self.waf_profile.confidence}
        - Signatures: {len(self.waf_profile.signatures)} detected
        - Rate Limiting: {self.waf_profile.rate_limit_detected}
        
        Recommend 5-8 evasion techniques from:
        - payload_encoding (URL encoding, base64, etc.)
        - request_fragmentation (splitting payloads)
        - timing_delays (random delays)
        - header_manipulation (custom headers)
        - request_ordering (different parameter order)
        - case_variation (mixed case payloads)
        - comment_injection (SQL comment injection)
        - whitespace_variation (tab, newline insertion)
        - protocol_variation (HTTP/1.0 vs HTTP/1.1)
        - user_agent_rotation (different UA strings)
        
        Return as JSON: {{"techniques": ["payload_encoding", "timing_delays"]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",
                prompt=prompt,
                max_tokens=300,
                task_type="pattern_recognition",
            )

            if result.get("output"):
                try:
                    analysis = json.loads(result["output"])
                    return analysis.get("techniques", [])

                except json.JSONDecodeError:
                    logger.warning("AI evasion techniques response not valid JSON")

        except Exception as e:
            logger.error(f"AI evasion techniques analysis failed: {e}")

        return ["payload_encoding", "timing_delays"]  # Default techniques

    async def _configure_stealth_mode(self) -> None:
        """Configure stealth mode settings"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Configuring stealth mode...", phase="waf_analysis"
        )

        if not self.waf_profile:
            self.stealth_config["stealth_mode"] = False
            return

        # Determine if stealth mode should be enabled
        stealth_conditions = [
            self.waf_profile.confidence > 0.7,
            self.waf_profile.rate_limit_detected,
            self.waf_profile.waf_type
            in [WAFType.CLOUDFLARE, WAFType.AKAMAI, WAFType.IMPERVA],
        ]

        self.waf_profile.stealth_mode = any(stealth_conditions)
        self.stealth_config["stealth_mode"] = self.waf_profile.stealth_mode

        # Configure additional stealth settings
        self.stealth_config.update(
            {
                "random_delay_range": (0.8, 1.2),  # ±20% variation
                "user_agent_rotation": True,
                "header_randomization": True,
                "request_jitter": True,
                "exponential_backoff": self.waf_profile.rate_limit_detected,
            }
        )

    async def _initialize_proxy_configuration(self) -> None:
        """Initialize proxy configuration from environment variables"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Initializing proxy configuration...",
            phase="waf_analysis",
        )

        # Get proxy providers from environment
        proxy_providers_env = os.getenv("PROXY_PROVIDERS", "").split(",")
        proxy_providers_env = [p.strip() for p in proxy_providers_env if p.strip()]

        # Configure available proxy providers
        for provider_name in proxy_providers_env:
            if provider_name in self.proxy_providers:
                api_key = os.getenv(f"{provider_name.upper()}_API_KEY", "")
                if api_key:
                    self.proxy_config["providers"].append(
                        {
                            "name": provider_name,
                            "api_key": api_key,
                            "config": self.proxy_providers[provider_name],
                        }
                    )

        # Enable proxy rotation if providers are available
        if self.proxy_config["providers"]:
            self.proxy_config["enabled"] = True
            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f'Proxy rotation enabled with {len(self.proxy_config["providers"])} providers',
                phase="waf_analysis",
            )

    async def rotate_proxy(self) -> bool:
        """Rotate to next proxy provider"""
        if not self.proxy_config["enabled"] or not self.proxy_config["providers"]:
            return False

        # Move to next provider
        self.proxy_config["current_provider_index"] = (
            self.proxy_config["current_provider_index"] + 1
        ) % len(self.proxy_config["providers"])

        self.proxy_config["rotation_count"] += 1

        current_provider = self.proxy_config["providers"][
            self.proxy_config["current_provider_index"]
        ]

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f'Rotated to proxy provider: {current_provider["name"]} (rotation #{self.proxy_config["rotation_count"]})',
            phase="waf_analysis",
        )

        return True

    async def get_current_proxy_config(self) -> Dict[str, Any]:
        """Get current proxy configuration for requests"""
        if not self.proxy_config["enabled"] or not self.proxy_config["providers"]:
            return {}

        current_provider = self.proxy_config["providers"][
            self.proxy_config["current_provider_index"]
        ]

        # Get proxy endpoint from provider API
        proxy_endpoint = await self._get_proxy_endpoint(current_provider)

        if proxy_endpoint:
            return {
                "http": proxy_endpoint,
                "https": proxy_endpoint,
                "provider": current_provider["name"],
            }

        return {}

    async def _get_proxy_endpoint(self, provider: Dict[str, Any]) -> Optional[str]:
        """Get proxy endpoint from provider API"""
        try:
            config = provider["config"]
            headers = {config["auth_header"]: provider["api_key"]}

            # Make request to get proxy endpoint
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{config['api_url']}/proxy", headers=headers, timeout=10
                )

                if response.status_code == 200:
                    proxy_data = response.json()
                    return proxy_data.get("proxy", {}).get("endpoint")

        except Exception as e:
            logger.debug(f'Failed to get proxy endpoint from {provider["name"]}: {e}')

        return None

    async def handle_bypass_failure(self, bypass_type: str) -> None:
        """Handle bypass failure and trigger proxy rotation if needed"""
        self.proxy_config["bypass_failure_count"] += 1

        await self.ws_manager.send_log(
            self.session_id,
            "warning",
            f'Bypass failure detected: {bypass_type} (failure count: {self.proxy_config["bypass_failure_count"]})',
            phase="waf_analysis",
        )

        # Check if proxy rotation should be triggered
        if (
            bypass_type in ["xss_bypass", "sql_injection_bypass"]
            and self.proxy_config["bypass_failure_count"]
            >= self.proxy_config["rotation_threshold"]
        ):

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                "Triggering proxy rotation due to bypass failures",
                phase="waf_analysis",
            )

            await self.rotate_proxy()
            self.proxy_config["bypass_failure_count"] = 0

    def _compile_results(self) -> Dict[str, Any]:
        """Compile WAF analysis results"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "module": "waf_analyzer",
            "waf_profile": {
                "waf_type": (
                    self.waf_profile.waf_type.value if self.waf_profile else "unknown"
                ),
                "confidence": self.waf_profile.confidence if self.waf_profile else 0.0,
                "signatures_count": (
                    len(self.waf_profile.signatures) if self.waf_profile else 0
                ),
                "rate_limit_detected": (
                    self.waf_profile.rate_limit_detected if self.waf_profile else False
                ),
                "rate_limit_threshold": self.waf_profile.rate_limit_threshold,
                "recommended_delay": (
                    self.waf_profile.recommended_delay if self.waf_profile else 0.0
                ),
                "stealth_mode": (
                    self.waf_profile.stealth_mode if self.waf_profile else False
                ),
                "evasion_techniques": (
                    self.waf_profile.evasion_techniques if self.waf_profile else []
                ),
            },
            "stealth_config": self.stealth_config,
            "summary": {
                "waf_detected": self.waf_profile is not None
                and self.waf_profile.waf_type != WAFType.UNKNOWN,
                "waf_type": (
                    self.waf_profile.waf_type.value if self.waf_profile else "unknown"
                ),
                "confidence": self.waf_profile.confidence if self.waf_profile else 0.0,
                "recommended_delay": self.stealth_config.get("recommended_delay", 0.0),
                "stealth_mode_enabled": self.stealth_config.get("stealth_mode", False),
                "evasion_techniques_count": len(
                    self.stealth_config.get("evasion_techniques", [])
                ),
                "recommendation": "Use recommended delays and evasion techniques for stealthy scanning",
            },
        }
