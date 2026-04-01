"""Lightweight payload testing service for quick vulnerability detection."""

import re
from typing import Any

import httpx

from app.core.config import settings


class PayloadTester:
    """Lightweight async payload tester for reflection detection and response diffing."""

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout = timeout_seconds
        self.max_response_size = 50000  # 50KB max for analysis

    async def test_payload(
        self,
        url: str,
        payload: str,
        parameter_name: str,
        parameter_location: str = "query",
    ) -> dict[str, Any]:
        """
        Test a single payload against a URL and detect reflection/anomalies.

        Returns: {
            "status": int,
            "reflected": bool,
            "response_snippet": str,
            "confidence": int (0-100),
            "findings": [str],
        }
        """
        findings = []
        reflected = False
        confidence = 0

        try:
            # Get baseline response
            baseline_resp = await self._get_response(url, {})
            if not baseline_resp:
                return {
                    "status": 0,
                    "reflected": False,
                    "response_snippet": "Failed to get baseline",
                    "confidence": 0,
                    "findings": ["Unable to establish baseline"],
                }

            baseline_status = baseline_resp["status"]
            baseline_body = baseline_resp["body"]
            baseline_length = len(baseline_body)

            # Test with payload
            params = {parameter_name: payload}
            test_resp = await self._get_response(url, params)
            if not test_resp:
                return {
                    "status": 0,
                    "reflected": False,
                    "response_snippet": "Failed to test payload",
                    "confidence": 0,
                    "findings": ["Unable to execute test"],
                }

            test_status = test_resp["status"]
            test_body = test_resp["body"]
            test_length = len(test_body)

            response_snippet = test_body[:200]

            # Check for reflection
            reflected = self._check_reflection(payload, test_body)
            if reflected:
                findings.append(f"Payload reflected in response")
                confidence += 50

            # Check status code anomalies
            if test_status != baseline_status:
                findings.append(f"Status code changed: {baseline_status} → {test_status}")
                if test_status in (500, 502, 503):
                    confidence += 20
                    findings.append("Server error status detected")

            # Check response size anomaly
            if abs(test_length - baseline_length) > baseline_length * 0.5:
                findings.append(f"Response size changed: {baseline_length} → {test_length}")
                confidence += 15

            # Check for common error patterns indicating injection
            error_patterns = [
                r"(?i)(syntax error|mysql error|sql error|database error)",
                r"(?i)(undefined variable|variable is not defined)",
                r"(?i)(template error|jinja|django)",
            ]
            for pattern in error_patterns:
                if re.search(pattern, test_body[:5000]):  # Check first 5KB only
                    findings.append(f"Injected error pattern detected")
                    confidence += 20
                    break

            return {
                "status": test_status,
                "reflected": reflected,
                "response_snippet": response_snippet,
                "confidence": min(confidence, 100),
                "findings": findings,
            }

        except Exception as e:
            return {
                "status": 0,
                "reflected": False,
                "response_snippet": f"Error: {str(e)[:100]}",
                "confidence": 0,
                "findings": [f"Test error: {str(e)}"],
            }

    async def _get_response(self, url: str, params: dict) -> dict | None:
        """Get HTTP response with reasonable timeout."""
        try:
            timeout = httpx.Timeout(self.timeout, connect=self.timeout)
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(url, params=params)
                body = resp.text[: self.max_response_size]
                return {"status": resp.status_code, "body": body}
        except Exception:
            return None

    def _check_reflection(self, payload: str, response: str) -> bool:
        """Check if payload is reflected in response (simple substring check)."""
        # Escape special regex chars in payload for basic matching
        escaped_payload = re.escape(payload)
        # Check for exact or nearly-exact match (allowing for some encoding)
        return bool(re.search(escaped_payload, response, re.IGNORECASE))

    def _extract_error_context(self, response: str, max_length: int = 300) -> str:
        """Extract error message context from response."""
        lines = response.split("\n")
        error_context = []
        for line in lines:
            if any(keyword in line.lower() for keyword in ["error", "exception", "warning", "syntax"]):
                error_context.append(line.strip())
        return " | ".join(error_context[:3]) if error_context else ""


class OpportunityDetector:
    """Detect testing opportunities based on endpoint parameters."""

    @staticmethod
    def detect_opportunities(
        endpoint_url: str,
        parameters: list[str],
    ) -> list[dict[str, Any]]:
        """
        Detect potential testing opportunities for an endpoint.

        Returns: [{
            "parameter_name": str,
            "parameter_location": str,
            "vulnerability_types": [str],
            "confidence": int,
            "reason": str,
        }]
        """
        opportunities = []

        for param in parameters or []:
            param_lower = param.lower()

            # Detect XSS opportunities
            xss_indicators = [
                "search", "q", "query", "content", "text", "name", "message",
                "title", "description", "comment", "email", "username", "input",
            ]
            if any(indicator in param_lower for indicator in xss_indicators):
                opportunities.append({
                    "parameter_name": param,
                    "parameter_location": "query",
                    "vulnerability_types": ["xss", "blind_xss"],
                    "confidence": 70,
                    "reason": "Text input parameter likely reflects user data",
                })

            # Detect SQLi opportunities
            sqli_indicators = [
                "id", "user_id", "page", "sort", "filter", "search", "q",
                "db", "table", "where", "select",
            ]
            if any(indicator in param_lower for indicator in sqli_indicators):
                opportunities.append({
                    "parameter_name": param,
                    "parameter_location": "query",
                    "vulnerability_types": ["sqli"],
                    "confidence": 65,
                    "reason": "Parameter used in potential database query",
                })

            # Detect SSTI opportunities
            ssti_indicators = [
                "template", "render", "theme", "style", "format", "lang", "language",
            ]
            if any(indicator in param_lower for indicator in ssti_indicators):
                opportunities.append({
                    "parameter_name": param,
                    "parameter_location": "query",
                    "vulnerability_types": ["ssti"],
                    "confidence": 55,
                    "reason": "Parameter may control template rendering",
                })

            # Detect SSRF opportunities
            ssrf_indicators = [
                "url", "uri", "link", "redirect", "fetch", "load", "source",
                "proxy", "endpoint", "host", "server",
            ]
            if any(indicator in param_lower for indicator in ssrf_indicators):
                opportunities.append({
                    "parameter_name": param,
                    "parameter_location": "query",
                    "vulnerability_types": ["ssrf"],
                    "confidence": 60,
                    "reason": "Parameter accepts URL-like input",
                })

            # Detect Open Redirect opportunities
            redirect_indicators = [
                "redirect", "return", "next", "goto", "back", "origin", "referer",
                "callback", "returnurl", "destination", "url", "uri", "link",
            ]
            if any(indicator in param_lower for indicator in redirect_indicators):
                opportunities.append({
                    "parameter_name": param,
                    "parameter_location": "query",
                    "vulnerability_types": ["openredirect"],
                    "confidence": 75,
                    "reason": "Parameter controls redirect destination",
                })

        # Deduplicate by parameter name, keeping highest confidence
        seen = {}
        for opp in opportunities:
            param = opp["parameter_name"]
            if param not in seen or opp["confidence"] > seen[param]["confidence"]:
                seen[param] = opp

        return list(seen.values())
