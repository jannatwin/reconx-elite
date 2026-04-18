"""Phase 3: DualSessionHandler - Crawl with two sessions to find IDOR targets."""

from typing import Any

import httpx


class DualSessionHandler:
    """Crawl application with two different sessions to identify resource IDs and potential IDOR targets."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session_a_resources: dict[str, list[dict[str, Any]]] = {}
        self.session_b_resources: dict[str, list[dict[str, Any]]] = {}
        self.idor_candidates: list[dict[str, Any]] = []

    async def crawl_with_dual_sessions(
        self, session_a_token: str, session_b_token: str, endpoints: list[str]
    ) -> dict[str, Any]:
        """Crawl endpoints with two sessions and identify IDOR candidates."""
        # Crawl as Session A
        await self._crawl_endpoints(session_a_token, endpoints, "session_a")

        # Crawl as Session B
        await self._crawl_endpoints(session_b_token, endpoints, "session_b")

        # Identify IDOR candidates
        idor_candidates = await self._identify_idor_candidates()

        return {
            "session_a_resources": len(self.session_a_resources),
            "session_b_resources": len(self.session_b_resources),
            "idor_candidates": idor_candidates,
            "total_candidates": len(idor_candidates),
        }

    async def _crawl_endpoints(
        self, session_token: str, endpoints: list[str], session_label: str
    ) -> None:
        """Crawl endpoints with a specific session token."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            for endpoint in endpoints:
                try:
                    headers = {"Authorization": f"Bearer {session_token}"}
                    response = await client.get(
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        follow_redirects=True,
                    )

                    if response.status_code == 200:
                        # Extract resource IDs from response
                        resources = await self._extract_resources(
                            response.text, endpoint
                        )

                        if session_label == "session_a":
                            self.session_a_resources[endpoint] = resources
                        else:
                            self.session_b_resources[endpoint] = resources

                except Exception:
                    pass

    async def _extract_resources(
        self, html_content: str, endpoint: str
    ) -> list[dict[str, Any]]:
        """Extract resource IDs from HTML/JSON response."""
        resources = []

        # Look for common ID patterns
        import re

        # JSON IDs: "id": 123 or "userId": "456"
        json_ids = re.findall(
            r'"(?:id|userId|resourceId|itemId)"\s*:\s*(?:"?(\d+|[a-f0-9\-]+)"?)',
            html_content,
        )

        # UUID patterns
        uuid_pattern = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
        uuids = re.findall(uuid_pattern, html_content, re.IGNORECASE)

        for resource_id in json_ids + uuids:
            resources.append(
                {
                    "id": resource_id,
                    "endpoint": endpoint,
                    "id_type": "numeric" if resource_id.isdigit() else "uuid",
                    "tagged": "Potential-IDOR-Target",
                }
            )

        return resources

    async def _identify_idor_candidates(self) -> list[dict[str, Any]]:
        """Compare sessions to find endpoints accessed by both with resource IDs."""
        candidates = []

        # Find common endpoints
        common_endpoints = set(self.session_a_resources.keys()) & set(
            self.session_b_resources.keys()
        )

        for endpoint in common_endpoints:
            resources_a = self.session_a_resources[endpoint]
            resources_b = self.session_b_resources[endpoint]

            # Find resource IDs accessed by A that might be accessed by B
            if resources_a and resources_b:
                candidates.append(
                    {
                        "endpoint": endpoint,
                        "session_a_resources": [r["id"] for r in resources_a],
                        "session_b_resources": [r["id"] for r in resources_b],
                        "testing_strategy": "Cross-session resource access testing",
                        "priority": "HIGH",
                    }
                )

        return candidates

    async def test_idor_vector(
        self, endpoint: str, session_a_id: str, session_b_token: str
    ) -> dict[str, Any]:
        """Test if Session B can access Session A's resources (IDOR proof)."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                test_url = f"{self.base_url}{endpoint}?id={session_a_id}"
                headers = {"Authorization": f"Bearer {session_b_token}"}
                response = await client.get(
                    test_url, headers=headers, follow_redirects=True
                )

                return {
                    "endpoint": endpoint,
                    "accessed_id": session_a_id,
                    "status_code": response.status_code,
                    "vulnerable": response.status_code == 200,
                    "response_size": len(response.content),
                    "data_leaked": (
                        "potential data disclosure"
                        if response.status_code == 200
                        else "protected"
                    ),
                }
        except Exception as e:
            return {
                "endpoint": endpoint,
                "accessed_id": session_a_id,
                "error": str(e),
                "vulnerable": False,
            }
