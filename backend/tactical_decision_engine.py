import logging
from typing import Any

logger = logging.getLogger(__name__)


class TacticalDecisionEngine:
    """AI-driven attack strategy decision engine based on detected tech stack."""

    def __init__(self, model_router: Any):
        self.model_router = model_router
        self.priority_matrix = {
            "graphql": ["graphql_injection", "idor"],
            "aws": ["ssrf_metadata", "s3_misconfiguration"],
            "jwt": ["jwt_attacks", "session_bypass"],
            "checkout": ["business_logic", "price_manipulation"],
            "rest_api": ["idor", "input_validation"],
            "oauth": ["auth_bypass", "redirect_issues"],
        }
        self.big_7_vulns = [
            "BAC_IDOR",
            "Injection",
            "SSRF",
            "Misconfiguration",
            "XSS",
            "Auth_Session",
            "Business_Logic",
        ]

    async def decide_attack_vectors(
        self, tech_profile: dict[str, list[str]]
    ) -> dict[str, Any]:
        """Given tech stack, decide which vulnerabilities to prioritize."""
        logger.info(f"Deciding attack vectors based on tech profile")

        decision = {
            "tech_stack": tech_profile,
            "recommended_vectors": [],
            "priority_order": [],
            "reasoning": {},
        }

        tech_str = " ".join(
            str(v) for vals in tech_profile.values() for v in vals
        ).lower()

        if "graphql" in tech_str:
            decision["recommended_vectors"].extend(["GraphQL Injection", "IDOR"])
            decision["reasoning"][
                "graphql"
            ] = "GraphQL detected - test for introspection and nested query attacks"

        if "aws" in tech_str:
            decision["recommended_vectors"].extend(
                ["SSRF Metadata", "S3 Misconfiguration"]
            )
            decision["reasoning"][
                "aws"
            ] = "AWS detected - target 169.254.169.254 metadata endpoint and S3 bucket misconfigs"

        if "jwt" in tech_str:
            decision["recommended_vectors"].extend(["JWT Attacks", "Session Bypass"])
            decision["reasoning"][
                "jwt"
            ] = "JWT detected - test algorithm bypass, weak keys, signature validation"

        if "checkout" in tech_str or "payment" in tech_str or "cart" in tech_str:
            decision["recommended_vectors"].extend(
                ["Business Logic", "Price Manipulation"]
            )
            decision["reasoning"][
                "checkout"
            ] = "Checkout flow detected - focus on price/quantity manipulation and discount bypass"

        if "rest api" in tech_str:
            decision["recommended_vectors"].extend(["IDOR", "Input Validation"])
            decision["reasoning"][
                "rest_api"
            ] = "REST API detected - enumerate endpoints and test for horizontal privilege escalation"

        decision["priority_order"] = list(
            dict.fromkeys(decision["recommended_vectors"])
        )

        return decision

    async def tactical_report(
        self,
        tech_profile: dict[str, list[str]],
        decision_vector: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate a tactical report explaining attack vector selection."""
        report = {
            "target_tech_stack": tech_profile,
            "decision_rationale": decision_vector.get("reasoning", {}),
            "prioritized_vectors": decision_vector.get("priority_order", []),
            "findings_by_vector": {},
            "big_7_coverage": {},
        }

        for vuln_type in self.big_7_vulns:
            matching_findings = [
                f for f in findings if vuln_type in f.get("vuln_type", "")
            ]
            report["big_7_coverage"][vuln_type] = {
                "count": len(matching_findings),
                "findings": matching_findings,
            }

        return report
