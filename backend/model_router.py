import json
import logging
from typing import Any

from backend.ai_router import AIRouter

logger = logging.getLogger(__name__)


class ModelRouter:
    """Routes analysis tasks to appropriate AI models based on task type."""

    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router
        self.task_model_map = {
            "tech_profiling": "fast_classifier",
            "idor_analysis": "primary_analyst",
            "jwt_analysis": "chain_reasoner",
            "graphql_analysis": "deep_analyst",
            "ssrf_analysis": "chain_reasoner",
            "xss_payload_gen": "code_engine",
            "business_logic": "deep_analyst",
            "simulation": "code_engine",
            "payload_refine": "code_engine",
        }

    async def route_analysis(
        self, task_type: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route analysis to appropriate model based on task type."""
        model_role = self.task_model_map.get(task_type, "primary_analyst")

        prompt = self._build_prompt(task_type, context)
        result = await self.ai_router.call_model(
            role=model_role,
            prompt=prompt,
            max_tokens=4096,
        )
        return {
            "task": task_type,
            "model": result.get("model"),
            "role": model_role,
            "output": result.get("output"),
            "error": result.get("error"),
        }

    def _build_prompt(self, task_type: str, context: dict[str, Any]) -> str:
        """Build task-specific prompt."""
        if task_type == "tech_profiling":
            techs = context.get("technologies", {})
            return f"Analyze this tech stack and suggest top 3 attack vectors: {json.dumps(techs)}"

        if task_type == "idor_analysis":
            endpoints = context.get("endpoints", [])
            return f"These endpoints likely have IDOR vulnerabilities based on numeric/UUID parameters: {json.dumps(endpoints)}. Suggest test cases."

        if task_type == "jwt_analysis":
            token = context.get("token", "")
            return f"Analyze this JWT token for vulnerabilities: {token}. Check alg field, key strength, etc."

        if task_type == "graphql_analysis":
            url = context.get("url", "")
            return f"Test GraphQL endpoint {url} for introspection and nested query depth issues."

        if task_type == "ssrf_analysis":
            params = context.get("parameters", [])
            return f"These parameters might be vulnerable to SSRF (check for URL-like values): {json.dumps(params)}. Suggest payloads targeting 169.254.169.254 and internal IPs."

        if task_type == "xss_payload_gen":
            context_info = context.get("context", "")
            return (
                f"Generate context-aware XSS payloads for this context: {context_info}"
            )

        if task_type == "business_logic":
            flow = context.get("flow", "")
            return f"Analyze this checkout/payment flow for business logic flaws: {flow}. Focus on price manipulation and quantity bypass."

        if task_type == "simulation":
            request = context.get("request", {})
            payload = context.get("payload", {})
            tech_stack = context.get("tech_stack", [])
            return f"You are a backend server running {', '.join(tech_stack)}. Predict the HTTP status and JSON response for this request: {json.dumps(request)} with payload: {json.dumps(payload)}"

        if task_type == "payload_refine":
            original = context.get("original_payload", {})
            reason = context.get("rejection_reason", "")
            return f"The server rejected this payload because: {reason}. Refine it to bypass validation: {json.dumps(original)}"

        return "Analyze the security context and provide recommendations."

    async def analyze_tech_stack(
        self, technologies: dict[str, list[str]]
    ) -> dict[str, Any]:
        """Analyze tech stack and determine priority attack vectors."""
        result = await self.route_analysis(
            "tech_profiling", {"technologies": technologies}
        )
        return result

    async def analyze_idor_endpoints(
        self, endpoints: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Identify IDOR-vulnerable endpoints."""
        result = await self.route_analysis("idor_analysis", {"endpoints": endpoints})
        return result

    async def simulate_request(
        self,
        request_data: dict[str, Any],
        payload: dict[str, Any],
        tech_stack: list[str],
    ) -> dict[str, Any]:
        """Simulate server response to malicious payload."""
        result = await self.route_analysis(
            "simulation",
            {
                "request": request_data,
                "payload": payload,
                "tech_stack": tech_stack,
            },
        )
        return result

    async def refine_payload(
        self, original_payload: dict[str, Any], rejection_reason: str
    ) -> dict[str, Any]:
        """Refine payload to bypass server-side validation."""
        result = await self.route_analysis(
            "payload_refine",
            {
                "original_payload": original_payload,
                "rejection_reason": rejection_reason,
            },
        )
        return result
