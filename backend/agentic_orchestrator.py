"""Agentic Orchestrator - Central entry point for autonomous vulnerability research."""

import asyncio
import logging
from datetime import datetime
from typing import Any

from backend.ai_router import AIRouter
from backend.recon.recon_pipeline import ReconPipeline
from backend.recon.context_tree import ContextTree
from backend.predictive_sandbox import PredictiveSandbox
from backend.analyzers.logic_oracle import LogicOracle
from backend.phase_6_poc_generator import POCGenerator
from backend.phase_7_markdown_reporter import MarkdownReportGenerator
from backend.utils.cvss4_calculator import CVSS4Calculator
from backend.session_manifest import SessionManifest
from backend.websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


class AgenticOrchestrator:
    """
    Central orchestrator for agentic, multi-model vulnerability research.
    Replaces the 7-phase orchestrator with AI-driven autonomous flow.
    """

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter = None,
        ws_manager: WebSocketManager = None,
        session_tokens: dict[str, str] = None,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router or AIRouter()
        self.ws_manager = ws_manager
        self.session_tokens = session_tokens or {}

        # Initialize components
        self.recon_pipeline = ReconPipeline(target, self.ai_router)
        self.context_tree = self.recon_pipeline.context_tree
        self.predictive_sandbox = PredictiveSandbox(self.ai_router)
        self.logic_oracle = LogicOracle(self.ai_router)
        self.poc_generator = POCGenerator()
        self.report_generator = MarkdownReportGenerator()

        # Session manifest for state persistence
        self.manifest = SessionManifest(session_id)
        self.manifest.data["context_tree"]["target"] = target
        self.manifest.save()

    async def execute(self) -> dict[str, Any]:
        """Execute complete autonomous vulnerability research pipeline."""
        start_time = datetime.utcnow()

        try:
            await self._send_log(
                "info", "Starting Agentic Vulnerability Research Pipeline"
            )

            # Phase 1: Enhanced Reconnaissance
            await self._send_log("info", "Phase 1: Enhanced Reconnaissance")
            recon_summary = await self.recon_pipeline.execute_full_recon()
            await self._send_log("success", f"Recon complete: {recon_summary}")

            # Phase 2: Technology Profiling (integrated in recon)
            await self._send_log("info", "Phase 2: Context Tree populated")

            # Phase 3-6: Vulnerability Testing
            findings = await self._execute_vulnerability_testing()

            # Phase 7: Report Generation
            await self._send_log("info", "Phase 7: Generating professional report")
            report_path = await self._generate_report(findings)

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            result = {
                "status": "complete",
                "session_id": self.session_id,
                "target": self.target,
                "duration_seconds": duration,
                "findings_count": len(findings),
                "report_path": str(report_path),
                "recon_summary": recon_summary,
            }

            await self._send_log("success", f"Pipeline complete in {duration:.2f}s")
            return result

        except Exception as e:
            await self._send_log("error", f"Pipeline failed: {str(e)}")
            logger.error(f"Agentic orchestrator failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "session_id": self.session_id,
                "error": str(e),
            }

    async def _execute_vulnerability_testing(self) -> list[dict[str, Any]]:
        """Execute all vulnerability testing phases."""
        all_findings = []

        # Get live hosts and endpoints from context tree
        live_hosts = self.context_tree.tree["subdomains"]["live"]
        api_endpoints = self.context_tree.tree["api_schema"]["endpoints"]

        if not live_hosts and not api_endpoints:
            await self._send_log(
                "warning",
                "No live hosts or endpoints found, skipping vulnerability testing",
            )
            return all_findings

        base_url = f"https://{self.target}"
        token = self.session_tokens.get("session_a", "")

        # Test 1: BAC & IDOR (if dual session tokens provided)
        if self.session_tokens.get("session_a") and self.session_tokens.get(
            "session_b"
        ):
            await self._send_log(
                "info", "Testing BAC & IDOR with dual-session validator"
            )
            idor_findings = await self._test_idor(api_endpoints, base_url, token)
            all_findings.extend(idor_findings)

        # Test 2: Business Logic
        await self._send_log("info", "Testing Business Logic vulnerabilities")
        logic_findings = await self._test_business_logic(api_endpoints, base_url, token)
        all_findings.extend(logic_findings)

        # Test 3: SSRF
        await self._send_log("info", "Testing SSRF vulnerabilities")
        ssrf_findings = await self._test_ssrf(api_endpoints, base_url, token)
        all_findings.extend(ssrf_findings)

        # Test 4: Misconfiguration
        await self._send_log("info", "Testing for misconfigurations")
        misconfig_findings = await self._test_misconfiguration(live_hosts, base_url)
        all_findings.extend(misconfig_findings)

        # Test 5: Injection (GraphQL, Command, Prompt)
        await self._send_log("info", "Testing injection vulnerabilities")
        injection_findings = await self._test_injection(api_endpoints, base_url, token)
        all_findings.extend(injection_findings)

        await self._send_log(
            "success", f"Vulnerability testing complete: {len(all_findings)} findings"
        )

        return all_findings

    async def _test_idor(
        self, endpoints: list, base_url: str, token: str
    ) -> list[dict]:
        """Test for IDOR vulnerabilities using dual-session comparison."""
        findings = []
        for endpoint in endpoints[:5]:
            if isinstance(endpoint, dict):
                path = endpoint.get("path", "")
            else:
                path = str(endpoint)

            test_payload = {"id": "1"}
            evaluation = await self.predictive_sandbox.evaluate_vulnerability(
                vuln_type="idor",
                endpoint=path,
                payload=test_payload,
                context_tree=self.context_tree.get_tree(),
                base_url=base_url,
                token=token,
            )

            if evaluation["decision"] == "executed" and evaluation.get("result"):
                findings.append(
                    {
                        "type": "idor",
                        "endpoint": path,
                        "severity": "HIGH",
                        "cvss": CVSS4Calculator.from_vulnerability_type("idor"),
                        "confidence": evaluation["confidence"],
                    }
                )

        return findings

    async def _test_business_logic(
        self, endpoints: list, base_url: str, token: str
    ) -> list[dict]:
        """Test for business logic vulnerabilities."""
        findings = []

        for endpoint in endpoints[:3]:
            if isinstance(endpoint, dict):
                path = endpoint.get("path", "")
            else:
                path = str(endpoint)

            negative_findings = await self.logic_oracle.test_negative_values(
                path, ["price", "quantity", "amount"], base_url, token
            )
            findings.extend(negative_findings)

        return findings

    async def _test_ssrf(
        self, endpoints: list, base_url: str, token: str
    ) -> list[dict]:
        """Test for SSRF vulnerabilities."""
        findings = []

        ssrf_targets = [
            "169.254.169.254/latest/meta-data",
            "127.0.0.1",
            "localhost",
        ]

        for endpoint in endpoints[:5]:
            if isinstance(endpoint, dict):
                path = endpoint.get("path", "")
            else:
                path = str(endpoint)

            for target in ssrf_targets:
                evaluation = await self.predictive_sandbox.evaluate_vulnerability(
                    vuln_type="ssrf",
                    endpoint=path,
                    payload={"url": target},
                    context_tree=self.context_tree.get_tree(),
                    base_url=base_url,
                    token=token,
                )

                if evaluation["decision"] == "executed":
                    findings.append(
                        {
                            "type": "ssrf",
                            "endpoint": path,
                            "target": target,
                            "severity": "HIGH",
                            "cvss": CVSS4Calculator.from_vulnerability_type("ssrf"),
                            "confidence": evaluation["confidence"],
                        }
                    )

        return findings

    async def _test_misconfiguration(
        self, live_hosts: list, base_url: str
    ) -> list[dict]:
        """Test for misconfigurations."""
        findings = []

        sensitive_paths = ["/.env", "/.git/config", "/config.json", "/api/docs"]

        for host in live_hosts[:5]:
            for path in sensitive_paths:
                evaluation = await self.predictive_sandbox.evaluate_vulnerability(
                    vuln_type="misconfiguration",
                    endpoint=path,
                    payload={},
                    context_tree=self.context_tree.get_tree(),
                    base_url=host if "://" in host else f"https://{host}",
                )

                if evaluation["decision"] == "executed":
                    findings.append(
                        {
                            "type": "misconfiguration",
                            "endpoint": path,
                            "host": host,
                            "severity": "MEDIUM",
                            "cvss": CVSS4Calculator.from_vulnerability_type(
                                "misconfiguration"
                            ),
                            "confidence": evaluation["confidence"],
                        }
                    )

        return findings

    async def _test_injection(
        self, endpoints: list, base_url: str, token: str
    ) -> list[dict]:
        """Test for injection vulnerabilities."""
        findings = []

        for endpoint in endpoints[:3]:
            if isinstance(endpoint, dict):
                path = endpoint.get("path", "")
            else:
                path = str(endpoint)

            if "graphql" in path.lower():
                evaluation = await self.predictive_sandbox.evaluate_vulnerability(
                    vuln_type="sql_injection",
                    endpoint=path,
                    payload={"query": "{__schema{types{name}}}"},
                    context_tree=self.context_tree.get_tree(),
                    base_url=base_url,
                    token=token,
                )

                if evaluation["decision"] == "executed":
                    findings.append(
                        {
                            "type": "graphql_introspection",
                            "endpoint": path,
                            "severity": "MEDIUM",
                            "cvss": CVSS4Calculator.from_vulnerability_type(
                                "sql_injection"
                            ),
                            "confidence": evaluation["confidence"],
                        }
                    )

        return findings

    async def _generate_report(self, findings: list[dict]) -> str:
        """Generate professional vulnerability report."""
        all_findings = {
            "idor": [f for f in findings if f.get("type") == "idor"],
            "ssrf": [f for f in findings if f.get("type") == "ssrf"],
            "business_logic": [
                f for f in findings if f.get("type") == "business_logic"
            ],
            "misconfiguration": [
                f for f in findings if f.get("type") == "misconfiguration"
            ],
            "injection": [f for f in findings if "injection" in f.get("type", "")],
        }

        for finding in findings[:5]:
            poc = await self.poc_generator.generate_poc(
                finding_type=finding.get("type", "generic"),
                endpoint=finding.get("endpoint", "/"),
                payload=finding.get("payload", {}),
                session_token=self.session_tokens.get("session_a", ""),
                base_url=f"https://{self.target}",
            )
            finding["poc"] = poc

        manifest_data = self.manifest.data
        manifest_data["context_tree"].update(self.context_tree.get_tree())

        markdown = self.report_generator.generate_report(
            target=self.target,
            all_findings=all_findings,
            manifest_data=manifest_data,
        )

        report_path = f"./reports/report_{self.target.replace('.', '_')}.md"
        self.manifest.update_phase(
            "phase_7", "completed", [{"report_path": report_path}]
        )

        return report_path

    async def _send_log(self, level: str, message: str):
        """Send log message via WebSocket if available."""
        if self.ws_manager:
            await self.ws_manager.send_log(self.session_id, level, message)
        else:
            log_func = getattr(logger, level.lower(), logger.info)
            log_func(message)
