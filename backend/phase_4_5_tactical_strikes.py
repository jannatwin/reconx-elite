"""Phase 4 & 5: Tactical Strikes and Advanced Injection - AI-Driven Exploitation."""

from typing import Any

from backend.ai_router import AIRouter
from backend.analyzers import (
    analyze_bac_idor,
    analyze_injection,
    analyze_ssrf,
    analyze_misconfiguration,
    analyze_xss,
    analyze_auth_session,
    analyze_business_logic,
)


class TacticalStrikesOrchestrator:
    """Coordinate Phase 4 vulnerability-specific strikes using Qwen3 Coder."""

    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router
        self.model_role = "code_engine"  # Routes to Qwen3 Coder

    async def execute_bac_idor_strikes(
        self, endpoints: list[dict[str, Any]], session_token: str = ""
    ) -> list[dict[str, Any]]:
        """Execute BAC/IDOR attacks via cross-session and privilege escalation testing."""
        findings = []

        for endpoint in endpoints:
            if endpoint.get("method") == "GET":
                # Check for ID parameters (uuid, numeric ID)
                if (
                    "id" in str(endpoint.get("params", [])).lower()
                    or "uuid" in str(endpoint).lower()
                ):
                    payload_prompt = f"""Generate 5 different test payloads for IDOR attack on:
                    Endpoint: {endpoint.get('path')}
                    Parameters: {endpoint.get('params', [])}
                    
                    Return JSON with payloads array containing test IDs."""

                    result = await self.ai_router.call_model(
                        self.model_role, payload_prompt, max_tokens=300
                    )
                    if result.get("output"):
                        findings.append(
                            {
                                "type": "BAC/IDOR",
                                "endpoint": endpoint.get("path"),
                                "strategy": result.get("output", ""),
                                "severity": "HIGH",
                            }
                        )

        return findings

    async def execute_ssrf_strikes(
        self, endpoints: list[dict[str, Any]], tech_stack: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Execute SSRF attacks on URL-fetching parameters."""
        findings = []

        # SSRF payloads targeting common internal resources
        ssrf_targets = [
            "http://localhost:8080",
            "http://127.0.0.1:6379",
            "http://169.254.169.254/latest/meta-data",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.170.2/",  # Azure
            "http://metadata.google.internal/computeMetadata/v1",
        ]

        for endpoint in endpoints:
            # Look for parameters that might accept URLs
            if any(
                param in str(endpoint).lower()
                for param in ["url", "endpoint", "webhook", "callback", "fetch"]
            ):
                prompt = f"""Generate SSRF exploitation tactics for:
                Endpoint: {endpoint.get('path')}
                Parameter: {endpoint.get('params', [])}
                Tech Stack: {tech_stack}
                
                Recommended targets:
                {', '.join(ssrf_targets[:3])}
                
                Return exploitation steps and expected responses."""

                result = await self.ai_router.call_model(
                    self.model_role, prompt, max_tokens=400
                )
                if result.get("output"):
                    findings.append(
                        {
                            "type": "SSRF",
                            "endpoint": endpoint.get("path"),
                            "tactics": result.get("output", ""),
                            "severity": "HIGH",
                        }
                    )

        return findings

    async def execute_business_logic_strikes(
        self, endpoints: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Execute business logic attacks targeting financial flows."""
        findings = []

        # Detect checkout/payment endpoints
        payment_keywords = [
            "checkout",
            "payment",
            "cart",
            "order",
            "purchase",
            "invoice",
            "price",
        ]

        for endpoint in endpoints:
            endpoint_path = endpoint.get("path", "").lower()
            if any(keyword in endpoint_path for keyword in payment_keywords):
                prompt = f"""Analyze business logic vulnerabilities in checkout flow:
                Endpoint: {endpoint.get('path')}
                Method: {endpoint.get('method', 'POST')}
                Parameters: {endpoint.get('params', [])}
                
                Generate attack scenarios for:
                1. Negative price manipulation
                2. Quantity abuse
                3. Discount stacking
                4. Race condition exploitation
                5. Currency/unit price manipulation
                
                Return JSON with attack_scenarios array."""

                result = await self.ai_router.call_model(
                    self.model_role, prompt, max_tokens=500
                )
                if result.get("output"):
                    findings.append(
                        {
                            "type": "Business Logic",
                            "endpoint": endpoint.get("path"),
                            "scenarios": result.get("output", ""),
                            "severity": "MEDIUM",
                        }
                    )

        return findings


class AdvancedInjectionOrchestrator:
    """Phase 5: GraphQL Introspection and Prompt Injection attacks."""

    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router
        self.model_role = "code_engine"  # Qwen3 Coder

    async def execute_graphql_strikes(
        self, graphql_endpoints: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Execute GraphQL introspection and query exhaustion attacks."""
        findings = []

        for endpoint in graphql_endpoints:
            if endpoint.get("type") == "GraphQL":
                # Step 1: Introspection
                introspection_prompt = f"""Generate a complete GraphQL introspection query for:
                Endpoint: {endpoint.get('path')}
                
                Return the full introspection query that will expose all types, queries, and mutations.
                Also suggest exploitation paths based on common GraphQL vulnerabilities."""

                introspection_result = await self.ai_router.call_model(
                    self.model_role, introspection_prompt, max_tokens=500
                )

                # Step 2: Query exhaustion
                exhaustion_prompt = f"""Generate deeply nested GraphQL queries to cause:
                1. Query complexity exhaustion
                2. Alias-based query batching
                3. Fragment cycling
                4. Circular reference exploitation
                
                Endpoint: {endpoint.get('path')}
                
                Return array of malicious queries."""

                exhaustion_result = await self.ai_router.call_model(
                    self.model_role, exhaustion_prompt, max_tokens=400
                )

                findings.append(
                    {
                        "type": "GraphQL Injection",
                        "endpoint": endpoint.get("path"),
                        "introspection": introspection_result.get("output", ""),
                        "exhaustion": exhaustion_result.get("output", ""),
                        "severity": "HIGH",
                    }
                )

        return findings

    async def execute_prompt_injection_strikes(
        self, endpoints: list[dict[str, Any]], tech_stack: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Execute prompt injection attacks against LLM/Chatbot endpoints."""
        findings = []

        # Detect LLM/Chatbot endpoints
        llm_keywords = [
            "chat",
            "ai",
            "chatbot",
            "gpt",
            "llm",
            "assistant",
            "ask",
            "query",
        ]

        for endpoint in endpoints:
            endpoint_path = endpoint.get("path", "").lower()
            if any(keyword in endpoint_path for keyword in llm_keywords) or any(
                keyword in str(tech_stack).lower() for keyword in llm_keywords
            ):

                jailbreak_prompt = f"""Generate a comprehensive jailbreak suite for LLM endpoints:
                Endpoint: {endpoint.get('path')}
                Parameters: {endpoint.get('params', [])}
                
                Include attacks for:
                1. System prompt leakage
                2. Model version disclosure
                3. Training data extraction
                4. Role-based prompt injection
                5. Token smuggling
                6. Instruction override
                
                Return array of jailbreak payloads with explanations."""

                result = await self.ai_router.call_model(
                    self.model_role, jailbreak_prompt, max_tokens=600
                )

                findings.append(
                    {
                        "type": "Prompt Injection",
                        "endpoint": endpoint.get("path"),
                        "jailbreak_suite": result.get("output", ""),
                        "severity": (
                            "CRITICAL"
                            if "system_prompt" in result.get("output", "").lower()
                            else "HIGH"
                        ),
                    }
                )

        return findings

    async def execute_injection_strikes(
        self, endpoints: list[dict[str, Any]], tech_stack: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Execute SQL, Command, and Code Injection attacks."""
        findings = []

        for endpoint in endpoints:
            injection_prompt = f"""Generate exploitable injection payloads for:
            Endpoint: {endpoint.get('path')}
            Method: {endpoint.get('method', 'GET')}
            Parameters: {endpoint.get('params', [])}
            Tech Stack: {tech_stack}
            
            Generate payloads for:
            1. SQL Injection (UNION, Boolean-based, Time-based)
            2. Command Injection (OS command execution)
            3. Template Injection
            4. Expression injection
            5. LDAP/NoSQL injection
            
            Return JSON with payload_sets array, each with type and examples."""

            result = await self.ai_router.call_model(
                self.model_role, injection_prompt, max_tokens=500
            )

            if result.get("output"):
                findings.append(
                    {
                        "type": "Injection",
                        "endpoint": endpoint.get("path"),
                        "payloads": result.get("output", ""),
                        "severity": "CRITICAL",
                    }
                )

        return findings
