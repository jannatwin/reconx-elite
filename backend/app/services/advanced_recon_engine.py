"""Advanced Recon Engine with Stealth, Fuzzing, and Discovery capabilities."""

import asyncio
import json
import logging
import random
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import settings
from app.models.advanced_recon import (
    StealthConfig,
    DiscoveredParameter,
    FuzzedEndpoint,
    SmartWordlist,
)

logger = logging.getLogger(__name__)


class StealthScanner:
    """Advanced stealth scanning engine with rate limiting and jitter."""

    def __init__(self, config: StealthConfig):
        self.config = config
        self.session = None
        self.user_agents = self._get_user_agents()
        self.request_count = 0
        self.last_request_time = 0

        # Rate limiting
        self.min_interval = 1.0 / max(config.requests_per_second, 1)

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0), follow_redirects=False, verify=False
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.aclose()

    def _get_user_agents(self) -> List[str]:
        """Get user agent list for rotation."""
        default_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
        ]

        if self.config.custom_user_agents:
            try:
                custom_agents = json.loads(self.config.custom_user_agents)
                return custom_agents + default_agents
            except json.JSONDecodeError:
                logger.warning("Invalid custom user agents JSON, using defaults")

        return default_agents

    def _get_random_user_agent(self) -> str:
        """Get random user agent."""
        if self.config.rotate_user_agents:
            return random.choice(self.user_agents)
        return self.user_agents[0]

    def _calculate_delay(self) -> float:
        """Calculate delay with jitter."""
        base_delay = random.uniform(
            self.config.random_delay_min / 1000.0, self.config.random_delay_max / 1000.0
        )

        if self.config.use_jitter:
            jitter = base_delay * (self.config.jitter_percentage / 100.0)
            return base_delay + random.uniform(-jitter, jitter)

        return base_delay

    async def _rate_limit(self):
        """Apply rate limiting with jitter."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        # Calculate required delay
        required_delay = self._calculate_delay()

        # Apply rate limiting
        if time_since_last < self.min_interval:
            await asyncio.sleep(self.min_interval - time_since_last)

        if required_delay > 0:
            await asyncio.sleep(required_delay)

        self.last_request_time = time.time()
        self.request_count += 1

    async def make_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make a stealth request with rate limiting."""
        await self._rate_limit()

        # Set headers
        headers = kwargs.get("headers", {})
        headers["User-Agent"] = self._get_random_user_agent()
        kwargs["headers"] = headers

        # Make request with retry logic
        for attempt in range(self.config.max_retries + 1):
            try:
                response = await self.session.request(method, url, **kwargs)

                # Log request for monitoring
                logger.debug(
                    f"Stealth request: {method} {url} -> {response.status_code}"
                )

                return response

            except httpx.RequestError as e:
                if attempt == self.config.max_retries:
                    raise

                # Exponential backoff
                backoff = (self.config.retry_backoff_factor**attempt) * 0.5
                logger.warning(f"Request failed, retrying in {backoff}s: {e}")
                await asyncio.sleep(backoff)

        raise Exception("Max retries exceeded")


class ParameterDiscovery:
    """Advanced parameter discovery engine."""

    def __init__(self):
        self.common_params = [
            # Common web parameters
            "id",
            "user",
            "username",
            "email",
            "token",
            "key",
            "secret",
            "redirect",
            "url",
            "return",
            "next",
            "callback",
            "ref",
            "file",
            "upload",
            "download",
            "path",
            "dir",
            "folder",
            "action",
            "method",
            "type",
            "format",
            "view",
            "mode",
            "page",
            "limit",
            "offset",
            "sort",
            "order",
            "filter",
            "search",
            "query",
            "q",
            "term",
            "keyword",
            "find",
            "lang",
            "language",
            "locale",
            "country",
            "region",
            "debug",
            "test",
            "dev",
            "staging",
            "admin",
            "config",
            # API parameters
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "client_id",
            "client_secret",
            "grant_type",
            "scope",
            "response_type",
            "state",
            "nonce",
            "code",
            # Security parameters
            "csrf_token",
            "authenticity_token",
            "samesite",
            "captcha",
            "challenge",
            "verification",
            "otp",
            # Technical parameters
            "version",
            "v",
            "build",
            "revision",
            "timestamp",
            "callback",
            "jsonp",
            "format",
            "output",
            "pretty",
        ]

    async def discover_parameters(
        self, base_url: str, stealth_scanner: StealthScanner, scan_id: int
    ) -> List[DiscoveredParameter]:
        """Discover parameters on endpoints."""

        discovered_params = []

        # Test each common parameter
        for param in self.common_params:
            try:
                # Test with GET parameter
                result = await self._test_parameter(
                    base_url, param, "query", scan_id, stealth_scanner
                )
                if result:
                    discovered_params.append(result)

                # Test with POST parameter if applicable
                result = await self._test_parameter(
                    base_url, param, "post", scan_id, stealth_scanner
                )
                if result:
                    discovered_params.append(result)

            except Exception as e:
                logger.warning(f"Parameter discovery failed for {param}: {e}")
                continue

        return discovered_params

    async def _test_parameter(
        self,
        base_url: str,
        param_name: str,
        param_type: str,
        scan_id: int,
        stealth_scanner: StealthScanner,
    ) -> Optional[DiscoveredParameter]:
        """Test a specific parameter."""

        test_values = ["test", "1", "true", "admin", "probe"]

        for value in test_values:
            try:
                # Make baseline request
                baseline_response = await stealth_scanner.make_request("GET", base_url)
                baseline_status = baseline_response.status_code
                baseline_length = len(baseline_response.content)

                # Make request with parameter
                if param_type == "query":
                    test_url = f"{base_url}?{param_name}={value}"
                    test_response = await stealth_scanner.make_request("GET", test_url)
                else:  # POST
                    test_response = await stealth_scanner.make_request(
                        "POST", base_url, data={param_name: value}
                    )

                # Analyze differences
                indicators = []
                confidence = 0

                # Status code change
                if test_response.status_code != baseline_status:
                    indicators.append(f"status_code_change:{test_response.status_code}")
                    confidence += 30

                # Response length change
                test_length = len(test_response.content)
                if abs(test_length - baseline_length) > 100:
                    indicators.append(
                        f"length_change:{abs(test_length - baseline_length)}"
                    )
                    confidence += 20

                # Reflection detection
                response_text = test_response.text.lower()
                if value.lower() in response_text:
                    indicators.append("reflection_detected")
                    confidence += 25

                # Interesting status codes
                if test_response.status_code in [200, 403, 401, 500]:
                    confidence += 15

                # Create discovered parameter if confidence is high enough
                if confidence >= 40:
                    return DiscoveredParameter(
                        scan_id=scan_id,
                        parameter_name=param_name,
                        parameter_type=param_type,
                        parameter_value=value,
                        discovery_method="parameter_bruteforce",
                        confidence_score=min(confidence, 100),
                        response_indicators=json.dumps(indicators),
                        status_code_change=test_response.status_code - baseline_status,
                        response_length_change=test_length - baseline_length,
                        reflection_detected="reflection_detected" in indicators,
                    )

            except Exception as e:
                logger.debug(f"Parameter test failed for {param_name}={value}: {e}")
                continue

        return None


class ContentFuzzer:
    """FFUF-style content fuzzing engine."""

    def __init__(self):
        self.common_wordlists = {
            "admin": [
                "admin",
                "administrator",
                "admin.php",
                "admin.html",
                "login",
                "signin",
                "auth",
                "authenticate",
                "dashboard",
                "panel",
                "control",
                "manage",
                "config",
                "configuration",
                "settings",
                "setup",
                "backup",
                "backup.php",
                "backup.sql",
                "dump",
                "test",
                "dev",
                "staging",
                "debug",
                "debug.php",
            ],
            "api": [
                "api",
                "v1",
                "v2",
                "v3",
                "rest",
                "graphql",
                "endpoint",
                "service",
                "microservice",
                "health",
                "status",
                "ping",
                "version",
                "info",
                "docs",
                "swagger",
                "openapi",
                "redoc",
                "postman",
            ],
            "files": [
                "robots.txt",
                "sitemap.xml",
                "sitemap.html",
                ".htaccess",
                ".htpasswd",
                "web.config",
                "index.php",
                "index.html",
                "index.jsp",
                "index.asp",
                "config.php",
                "config.inc",
                "config.cfg",
                "database.yml",
                "database.ini",
                "env",
                ".env",
                "log",
                "logs",
                "error.log",
                "access.log",
                "upload",
                "uploads",
                "files",
                "download",
                "tmp",
                "temp",
                "cache",
                "storage",
            ],
            "directories": [
                "admin",
                "api",
                "assets",
                "css",
                "js",
                "img",
                "images",
                "uploads",
                "files",
                "backup",
                "logs",
                "tmp",
                "cache",
                "config",
                "conf",
                "etc",
                "lib",
                "vendor",
                "node_modules",
                "src",
                "app",
                "public",
                "private",
                "secure",
                "hidden",
            ],
        }

    async def fuzz_content(
        self,
        base_url: str,
        wordlist_category: str,
        stealth_scanner: StealthScanner,
        scan_id: int,
    ) -> List[FuzzedEndpoint]:
        """Fuzz content with wordlist."""

        discovered_endpoints = []
        wordlist = self.common_wordlists.get(wordlist_category, [])

        for word in wordlist:
            try:
                # Construct test URL
                test_url = urljoin(base_url, word)

                # Make request
                response = await stealth_scanner.make_request("GET", test_url)

                # Analyze response
                if self._is_interesting_response(response):
                    endpoint = FuzzedEndpoint(
                        scan_id=scan_id,
                        url=test_url,
                        path=word,
                        method="GET",
                        status_code=response.status_code,
                        response_length=len(response.content),
                        response_time_ms=int(response.elapsed.total_seconds() * 1000),
                        is_interesting=True,
                        interest_reasons=json.dumps(
                            self._get_interest_reasons(response)
                        ),
                        content_type=response.headers.get("content-type", ""),
                        server_header=response.headers.get("server", ""),
                        wordlist_used=wordlist_category,
                        payload=word,
                    )
                    discovered_endpoints.append(endpoint)

            except Exception as e:
                logger.debug(f"Fuzz request failed for {word}: {e}")
                continue

        return discovered_endpoints

    def _is_interesting_response(self, response: httpx.Response) -> bool:
        """Determine if response is interesting."""

        # Ignore 404s
        if response.status_code == 404:
            return False

        # Interesting status codes
        if response.status_code in [200, 403, 401, 500, 502, 503]:
            return True

        # Interesting response sizes
        content_length = len(response.content)
        if content_length > 1000:  # Large responses
            return True

        # Content type analysis
        content_type = response.headers.get("content-type", "").lower()
        if any(ct in content_type for ct in ["json", "xml", "text/html"]):
            return True

        return False

    def _get_interest_reasons(self, response: httpx.Response) -> List[str]:
        """Get reasons why response is interesting."""

        reasons = []

        # Status code reasons
        if response.status_code == 200:
            reasons.append("successful_response")
        elif response.status_code == 403:
            reasons.append("access_denied")
        elif response.status_code == 401:
            reasons.append("authentication_required")
        elif response.status_code >= 500:
            reasons.append("server_error")

        # Content type reasons
        content_type = response.headers.get("content-type", "").lower()
        if "json" in content_type:
            reasons.append("json_content")
        elif "xml" in content_type:
            reasons.append("xml_content")
        elif "html" in content_type:
            reasons.append("html_content")

        # Size reasons
        content_length = len(response.content)
        if content_length > 5000:
            reasons.append("large_response")
        elif content_length < 100:
            reasons.append("small_response")

        # Header analysis
        server = response.headers.get("server", "").lower()
        if server:
            reasons.append(f"server:{server}")

        return reasons


class AdaptiveScanner:
    """Adaptive scanning intelligence."""

    def __init__(self):
        self.endpoint_patterns = {}
        self.successful_payloads = {}

    def analyze_endpoint(self, url: str, response: httpx.Response) -> Dict[str, any]:
        """Analyze endpoint for adaptive scanning."""

        analysis = {
            "endpoint_type": self._classify_endpoint(url, response),
            "recommended_techniques": [],
            "priority_level": "medium",
        }

        # Recommend techniques based on endpoint type
        if analysis["endpoint_type"] == "api":
            analysis["recommended_techniques"] = ["parameter_fuzzing", "api_discovery"]
            analysis["priority_level"] = "high"
        elif analysis["endpoint_type"] == "admin":
            analysis["recommended_techniques"] = ["parameter_fuzzing", "auth_testing"]
            analysis["priority_level"] = "high"
        elif analysis["endpoint_type"] == "login":
            analysis["recommended_techniques"] = ["parameter_fuzzing", "auth_bypass"]
            analysis["priority_level"] = "high"

        return analysis

    def _classify_endpoint(self, url: str, response: httpx.Response) -> str:
        """Classify endpoint type."""

        path = urlparse(url).path.lower()
        content_type = response.headers.get("content-type", "").lower()

        # API endpoints
        if any(
            indicator in path for indicator in ["api", "v1", "v2", "graphql", "rest"]
        ):
            return "api"

        # Admin endpoints
        if any(
            indicator in path for indicator in ["admin", "manage", "config", "settings"]
        ):
            return "admin"

        # Login endpoints
        if any(indicator in path for indicator in ["login", "signin", "auth", "oauth"]):
            return "login"

        # File endpoints
        if any(
            indicator in path for indicator in ["file", "upload", "download", "backup"]
        ):
            return "file"

        # Content endpoints
        if "html" in content_type or "json" in content_type:
            return "content"

        return "unknown"


# Global instances
stealth_scanner = StealthScanner
parameter_discovery = ParameterDiscovery
content_fuzzer = ContentFuzzer
adaptive_scanner = AdaptiveScanner
