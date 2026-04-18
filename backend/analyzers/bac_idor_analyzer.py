"""BAC & IDOR vulnerability analyzer - Dual-Session Validator."""

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class DualSessionValidator:
    """Compare responses between two user sessions to detect IDOR/BAC vulnerabilities."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url

    async def compare_responses(
        self,
        endpoint: str,
        session_a_token: str,
        session_b_token: str,
        resource_id: str,
        method: str = "GET",
        payload: dict = None,
    ) -> dict[str, Any]:
        """Test IDOR by comparing Response-A vs Response-B for the same resource."""
        url = f"{self.base_url}{endpoint}"
        params = {"id": resource_id} if method == "GET" else None
        json_payload = payload if method != "GET" else None

        response_a = await self._make_request(
            url, method, session_a_token, params, json_payload
        )
        response_b = await self._make_request(
            url, method, session_b_token, params, json_payload
        )

        return self._analyze_discrepancy(response_a, response_b, endpoint, resource_id)

    async def _make_request(
        self,
        url: str,
        method: str,
        token: str,
        params: dict = None,
        json_payload: dict = None,
    ) -> dict[str, Any]:
        """Make authenticated HTTP request."""
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=params)
                elif method == "POST":
                    response = await client.post(
                        url, headers=headers, json=json_payload
                    )
                else:
                    response = await client.get(url, headers=headers)

                return {
                    "status_code": response.status_code,
                    "body": response.text[:1000],
                    "content_length": len(response.content),
                }
        except Exception as e:
            return {"status_code": 0, "error": str(e)}

    def _analyze_discrepancy(
        self, response_a: dict, response_b: dict, endpoint: str, resource_id: str
    ) -> dict[str, Any]:
        """Analyze discrepancies between two session responses."""
        status_a = response_a.get("status_code")
        status_b = response_b.get("status_code")

        if status_a == 200 and status_b == 200:
            body_a = response_a.get("body", "")
            body_b = response_b.get("body", "")
            similarity = self._calculate_similarity(body_a, body_b)

            return {
                "vulnerable": True,
                "type": "idor",
                "endpoint": endpoint,
                "resource_id": resource_id,
                "severity": "HIGH",
                "details": f"Both sessions returned 200. Similarity: {similarity:.0%}",
                "body_similarity": similarity,
            }

        return {
            "vulnerable": False,
            "type": "access_control_ok",
            "endpoint": endpoint,
            "details": f"Status codes: A={status_a}, B={status_b}",
        }

    def _calculate_similarity(self, text_a: str, text_b: str) -> float:
        """Calculate similarity between two response bodies."""
        if not text_a or not text_b:
            return 0.0
        common_chars = sum(1 for a, b in zip(text_a, text_b) if a == b)
        max_len = max(len(text_a), len(text_b))
        return common_chars / max_len if max_len > 0 else 0.0


async def analyze_bac_idor(
    endpoints: list[dict[str, Any]], model_router: Any
) -> dict[str, Any]:
    """Analyze endpoints for Broken Access Control and IDOR vulnerabilities."""
    idor_candidates = []

    for endpoint in endpoints:
        path = endpoint.get("path", "")
        params = endpoint.get("parameters", [])

        uuid_pattern = (
            r"\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?"
        )
        numeric_pattern = r"\{?id\}?|\{?\d+\}?"

        if re.search(uuid_pattern, path, re.IGNORECASE) or re.search(
            numeric_pattern, path, re.IGNORECASE
        ):
            idor_candidates.append(
                {
                    "endpoint": path,
                    "method": endpoint.get("method", "GET"),
                    "parameter_type": (
                        "uuid" if re.search(uuid_pattern, path) else "numeric"
                    ),
                    "test_strategy": "Use DualSessionValidator to compare responses",
                }
            )

    return {
        "vulnerability": "BAC / IDOR",
        "candidates": idor_candidates,
        "recommendation": (
            f"Test {len(idor_candidates)} endpoints with dual-session validation"
            if idor_candidates
            else "No obvious IDOR endpoints found"
        ),
    }
