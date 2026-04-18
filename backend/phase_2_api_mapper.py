"""Phase 2: API Mapper - Categorize and extract endpoint schemas."""

import json
import re
from typing import Any

import httpx

from backend.ai_router import AIRouter


class APIMapper:
    """Identify and map REST, GraphQL, and SOAP endpoints with schema extraction."""

    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router
        self.endpoints = {"rest": [], "graphql": [], "soap": []}

    async def analyze_api_surface(
        self, urls: list[str], html_content: str = ""
    ) -> dict[str, Any]:
        """Categorize discovered URLs into API types."""
        endpoints = await self._extract_endpoints(urls, html_content)

        rest_endpoints = await self._identify_rest_endpoints(endpoints)
        graphql_endpoints = await self._identify_graphql_endpoints(endpoints)
        soap_endpoints = await self._identify_soap_endpoints(endpoints)

        return {
            "rest": rest_endpoints,
            "graphql": graphql_endpoints,
            "soap": soap_endpoints,
            "total": len(rest_endpoints) + len(graphql_endpoints) + len(soap_endpoints),
        }

    async def _extract_endpoints(
        self, urls: list[str], html_content: str = ""
    ) -> list[str]:
        """Extract API endpoints from URLs and HTML."""
        endpoints = list(urls)

        # Extract from HTML (check for XHR calls, fetch, API paths)
        api_patterns = [
            r"/api/(?:v\d+/)?[\w/]+",
            r"/rest/(?:v\d+/)?[\w/]+",
            r"/graphql",
            r"/soap",
            r"/service\.asmx",
            r"\.json\b",
            r"\.xml\b",
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            endpoints.extend(matches)

        return list(set(endpoints))

    async def _identify_rest_endpoints(
        self, endpoints: list[str]
    ) -> list[dict[str, Any]]:
        """Identify REST endpoints and extract available methods."""
        rest_endpoints = []

        for endpoint in endpoints:
            if (
                "/api/" in endpoint
                or "/rest/" in endpoint
                or endpoint.endswith((".json", ".xml"))
            ):
                # Basic REST indicators
                rest_endpoints.append(
                    {
                        "path": endpoint,
                        "type": "REST",
                        "methods": ["GET", "POST", "PUT", "DELETE"],  # Will be tested
                        "parameters": await self._extract_parameters(endpoint),
                    }
                )

        return rest_endpoints

    async def _identify_graphql_endpoints(
        self, endpoints: list[str]
    ) -> list[dict[str, Any]]:
        """Identify GraphQL endpoints and attempt introspection."""
        graphql_endpoints = []

        for endpoint in endpoints:
            if "/graphql" in endpoint.lower():
                # Try to fetch schema
                schema = await self._attempt_graphql_introspection(endpoint)
                graphql_endpoints.append(
                    {
                        "path": endpoint,
                        "type": "GraphQL",
                        "schema_available": bool(schema),
                        "operations": schema.get("operations", []) if schema else [],
                    }
                )

        return graphql_endpoints

    async def _identify_soap_endpoints(
        self, endpoints: list[str]
    ) -> list[dict[str, Any]]:
        """Identify SOAP endpoints and extract WSDL."""
        soap_endpoints = []

        for endpoint in endpoints:
            if (
                "/soap" in endpoint.lower()
                or ".asmx" in endpoint.lower()
                or ".svc" in endpoint.lower()
            ):
                wsdl = await self._fetch_wsdl(endpoint)
                soap_endpoints.append(
                    {
                        "path": endpoint,
                        "type": "SOAP",
                        "wsdl_available": bool(wsdl),
                        "methods": wsdl.get("methods", []) if wsdl else [],
                    }
                )

        return soap_endpoints

    async def _extract_parameters(self, endpoint: str) -> list[str]:
        """Extract parameter names from endpoint path."""
        # Look for patterns like {id}, [id], :id, etc.
        patterns = [r"\{(\w+)\}", r"\[(\w+)\]", r":(\w+)"]
        params = []
        for pattern in patterns:
            params.extend(re.findall(pattern, endpoint))
        return list(set(params))

    async def _attempt_graphql_introspection(
        self, graphql_endpoint: str
    ) -> dict[str, Any] | None:
        """Try to fetch GraphQL schema via introspection."""
        introspection_query = {
            "query": """
            query {
              __schema {
                types {
                  name
                  kind
                }
                queryType { name }
                mutationType { name }
              }
            }
            """
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(graphql_endpoint, json=introspection_query)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "operations": [
                            t["name"]
                            for t in data.get("data", {})
                            .get("__schema", {})
                            .get("types", [])
                        ],
                        "raw": data,
                    }
        except Exception:
            pass

        return None

    async def _fetch_wsdl(self, soap_endpoint: str) -> dict[str, Any] | None:
        """Fetch WSDL from SOAP endpoint."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{soap_endpoint}?wsdl")
                if response.status_code == 200:
                    # Parse WSDL to extract methods
                    methods = re.findall(r'<operation name="(\w+)"', response.text)
                    return {"methods": methods, "wsdl_text": response.text[:5000]}
        except Exception:
            pass

        return None
