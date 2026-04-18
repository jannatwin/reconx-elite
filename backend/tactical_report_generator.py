"""Tactical Report Generator - Explains AI chosen attack vectors for each scope."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TacticalReportGenerator:
    """Generates tactical reports explaining AI-driven attack decisions."""

    def __init__(self, reports_dir: str = "./tactical_reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)

    async def generate_report(
        self,
        target: str,
        tech_profile: dict[str, list[str]],
        decision_rationale: dict[str, str],
        all_findings: dict[str, Any],
        scope_summary: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate a comprehensive tactical report."""
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "target": target,
            "scope_summary": scope_summary,
            "technical_stack": tech_profile,
            "ai_decision_rationale": decision_rationale,
            "vulnerability_findings": {},
            "big_7_summary": {},
            "recommended_next_steps": [],
        }

        big_7 = [
            "BAC_IDOR",
            "Injection",
            "SSRF",
            "Misconfiguration",
            "XSS",
            "Auth_Session",
            "Business_Logic",
        ]

        for vuln in big_7:
            report["vulnerability_findings"][vuln] = all_findings.get(
                vuln.lower().replace("_", "_"), {}
            )
            candidates = all_findings.get(vuln.lower().replace("_", "_"), {}).get(
                "candidates", []
            ) or all_findings.get(vuln.lower().replace("_", "_"), {}).get(
                "total_candidates", 0
            )
            count = len(candidates) if isinstance(candidates, list) else candidates
            report["big_7_summary"][vuln] = {"count": count}

        report["recommended_next_steps"] = self._generate_recommendations(all_findings)

        report_file = (
            self.reports_dir
            / f'tactical_report_{target}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        )
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Tactical report generated: {report_file}")
        return report

    def _generate_recommendations(self, findings: dict[str, Any]) -> list[str]:
        """Generate prioritized next steps based on findings."""
        recommendations = []

        if findings.get("bac_idor", {}).get("candidates"):
            recommendations.append(
                "1. IDOR Testing: Use automated tools to enumerate user IDs and compare API responses"
            )

        if findings.get("injection", {}).get("graphql_findings"):
            recommendations.append(
                "2. GraphQL Introspection: Query __schema for full schema enumeration"
            )

        if findings.get("ssrf", {}).get("candidates"):
            recommendations.append(
                "3. SSRF Exploitation: Target 169.254.169.254/latest/meta-data on AWS instances"
            )

        if findings.get("misconfiguration", {}).get("exposed_secrets"):
            recommendations.append(
                "4. Secret Extraction: Leverage exposed API keys and tokens"
            )

        if findings.get("xss", {}).get("candidates"):
            recommendations.append(
                "5. XSS Payloads: Test DOM-based and stored XSS vectors"
            )

        if findings.get("auth_session", {}).get("jwt_findings"):
            recommendations.append(
                "6. JWT Analysis: Check for weak algorithm and key validation"
            )

        if findings.get("business_logic", {}).get("total_candidates"):
            recommendations.append(
                "7. Business Logic Testing: Use logic simulator to test price/discount bypass"
            )

        return recommendations

    def export_json(self, report: dict[str, Any], filename: str | None = None) -> str:
        """Export report as JSON."""
        if not filename:
            filename = f'tactical_report_{report["target"]}.json'
        filepath = self.reports_dir / filename
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)
        return str(filepath)
