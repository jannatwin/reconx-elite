"""7-Phase Orchestrator - Sequential state machine for autonomous vulnerability research."""

import asyncio
import os
import socket
from typing import Any

from backend.ai_router import AIRouter
from backend.phase_1_acquisition_mapper import AcquisitionMapper
from backend.phase_1_cloud_hunter import CloudHunter
from backend.phase_2_api_mapper import APIMapper
from backend.phase_2_cve_database import CVEDatabase
from backend.phase_3_dual_session_handler import DualSessionHandler
from backend.phase_4_5_tactical_strikes import (
    AdvancedInjectionOrchestrator,
    TacticalStrikesOrchestrator,
)
from backend.phase_6_poc_generator import POCGenerator
from backend.phase_7_markdown_reporter import MarkdownReportGenerator
from backend.session_manifest import SessionManifest

# Configurable sampling limits
SUBDOMAIN_SAMPLE_LIMIT = int(os.getenv("SUBDOMAIN_SAMPLE_LIMIT", "5"))
LIVE_HOST_SAMPLE_LIMIT = int(os.getenv("LIVE_HOST_SAMPLE_LIMIT", "10"))
POC_GENERATION_LIMIT = int(os.getenv("POC_GENERATION_LIMIT", "5"))
from backend.tech_profiler import TechProfiler
from backend.tool_runner import ToolRunner
from backend.websocket_manager import WebSocketManager


class SevenPhaseOrchestrator:
    """Orchestrate 7-phase autonomous vulnerability research pipeline."""

    def __init__(
        self,
        session_id: str,
        target: str,
        ws_manager: WebSocketManager,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        session_tokens: dict[str, str] | None = None,
    ):
        self.session_id = session_id
        self.target = target
        self.ws_manager = ws_manager
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.session_tokens = session_tokens or {}

        self.manifest = SessionManifest(session_id)
        self.manifest.data["context_tree"]["target"] = target
        self.manifest.save()

        # Initialize phase-specific modules
        self.cloud_hunter = CloudHunter(ai_router)
        self.acquisition_mapper = AcquisitionMapper(ai_router)
        self.cve_database = CVEDatabase()
        self.api_mapper = APIMapper(ai_router)
        self.tech_profiler = TechProfiler()
        self.poc_generator = POCGenerator()
        self.report_generator = MarkdownReportGenerator()

    async def execute(self) -> dict[str, Any]:
        """Execute complete 7-phase pipeline."""
        try:
            await self.phase_1_recursive_recon()
            await self.phase_2_context_aware_profiling()
            await self.phase_3_authenticated_analysis()
            await self.phase_4_vulnerability_strikes()
            await self.phase_5_advanced_injection()
            await self.phase_6_poc_generation()
            await self.phase_7_reporting()

            return {"status": "complete", "session_id": self.session_id}
        except Exception as e:
            await self.ws_manager.send_log(
                self.session_id, "error", f"Pipeline failed: {str(e)}", phase="error"
            )
            self.manifest.update_phase("phase_error", "failed", [{"error": str(e)}])
            return {"status": "failed", "error": str(e)}

    async def phase_1_recursive_recon(self) -> None:
        """Phase 1: Recursive Recon & Shadow Asset Mapping."""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting Phase 1: Recursive Recon",
            phase="phase_1",
        )

        try:
            # Recursive subdomain enumeration
            subdomains = await self.tool_runner.run_subfinder(self.target)
            self.manifest.add_context("subdomains", subdomains)

            # Non-standard port scanning
            non_std_ports = ["8080", "8443", "9000", "5000", "3000"]
            open_ports = {}

            # Apply sampling if needed
            if len(subdomains) > SUBDOMAIN_SAMPLE_LIMIT:
                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"Sampling {SUBDOMAIN_SAMPLE_LIMIT} subdomains from {len(subdomains)} total for port scanning",
                    phase="phase_1",
                )

            for subdomain in subdomains[:SUBDOMAIN_SAMPLE_LIMIT]:
                for port in non_std_ports:
                    if await self._check_port(subdomain, port):
                        if subdomain not in open_ports:
                            open_ports[subdomain] = []
                        open_ports[subdomain].append(port)

            self.manifest.add_context("open_ports", open_ports)

            # Cloud bucket hunting (CloudHunter)
            buckets = await self.cloud_hunter.hunt_buckets(self.target)
            if buckets.get("aws_s3"):
                self.manifest.add_context("cloud_buckets", buckets["aws_s3"])

            # Subsidiary discovery (AcquisitionMapper)
            acquisitions = await self.acquisition_mapper.map_acquisitions(self.target)
            if acquisitions.get("subsidiaries"):
                self.manifest.add_context("subsidiaries", acquisitions["subsidiaries"])

            self.manifest.update_phase(
                "phase_1",
                "completed",
                [
                    {
                        "subdomains": len(subdomains),
                        "cloud_buckets": len(buckets.get("aws_s3", [])),
                        "subsidiaries": len(acquisitions.get("subsidiaries", [])),
                    }
                ],
            )

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f'Phase 1 Complete: {len(subdomains)} subdomains, {len(buckets.get("aws_s3", []))} clouds, {len(acquisitions.get("subsidiaries", []))} entities',
                phase="phase_1",
            )
        except Exception as e:
            # Determine if this is a critical error that should halt the pipeline
            critical_errors = (ConnectionError, TimeoutError, OSError)
            if isinstance(e, critical_errors):
                # Critical error - halt pipeline
                await self.ws_manager.send_log(
                    self.session_id,
                    "error",
                    f"Phase 1 critical failure: {str(e)}",
                    phase="phase_1",
                )
                self.manifest.update_phase(
                    "phase_1", "failed", [{"error": str(e), "critical": True}]
                )
                raise  # Re-raise to halt pipeline
            else:
                # Non-critical error - log but continue
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    f"Phase 1 non-critical error: {str(e)}",
                    phase="phase_1",
                )
                self.manifest.update_phase(
                    "phase_1",
                    "completed_with_warnings",
                    [{"error": str(e), "critical": False}],
                )

    async def phase_2_context_aware_profiling(self) -> None:
        """Phase 2: Context-Aware Tech Profiling."""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting Phase 2: Tech Profiling & CVE Analysis",
            phase="phase_2",
        )

        try:
            live_hosts = self.manifest.data["context_tree"].get("live_hosts", [])
            if not live_hosts:
                live_hosts = await self.tool_runner.run_httpx_urls(
                    self.manifest.data["context_tree"].get("subdomains", [])
                )
                self.manifest.add_context("live_hosts", live_hosts)

            # Profile each host
            tech_stack = {}

            # Apply sampling if needed
            if len(live_hosts) > LIVE_HOST_SAMPLE_LIMIT:
                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"Sampling {LIVE_HOST_SAMPLE_LIMIT} hosts from {len(live_hosts)} total for tech profiling",
                    phase="phase_2",
                )

            for host in live_hosts[:LIVE_HOST_SAMPLE_LIMIT]:
                profile = await self.tech_profiler.profile_target(host, {}, [])
                if profile:
                    tech_stack.update(profile)

            self.manifest.add_context("tech_stack", tech_stack)

            # Check for low-hanging fruit CVEs
            cve_findings = self.cve_database.get_low_hanging_fruit(tech_stack)
            self.manifest.add_context("cve_findings", cve_findings)

            # API mapping
            endpoints = self.manifest.data["context_tree"].get("subdomains", [])
            api_surface = await self.api_mapper.analyze_api_surface(endpoints)
            self.manifest.add_context(
                "api_endpoints",
                api_surface.get("rest", []) + api_surface.get("graphql", []),
            )

            self.manifest.update_phase(
                "phase_2",
                "completed",
                [
                    {
                        "tech_stack_items": len(tech_stack),
                        "cve_findings": len(cve_findings),
                        "api_endpoints": len(
                            api_surface.get("rest", []) + api_surface.get("graphql", [])
                        ),
                    }
                ],
            )

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f'Phase 2 Complete: {len(tech_stack)} tech items, {len(cve_findings)} CVEs, {len(api_surface.get("rest", []))} REST endpoints',
                phase="phase_2",
            )
        except Exception as e:
            # Determine if this is a critical error that should halt the pipeline
            critical_errors = (ConnectionError, TimeoutError, OSError)
            if isinstance(e, critical_errors):
                # Critical error - halt pipeline
                await self.ws_manager.send_log(
                    self.session_id,
                    "error",
                    f"Phase 2 critical failure: {str(e)}",
                    phase="phase_2",
                )
                self.manifest.update_phase(
                    "phase_2", "failed", [{"error": str(e), "critical": True}]
                )
                raise  # Re-raise to halt pipeline
            else:
                # Non-critical error - log but continue
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    f"Phase 2 non-critical error: {str(e)}",
                    phase="phase_2",
                )
                self.manifest.update_phase(
                    "phase_2",
                    "completed_with_warnings",
                    [{"error": str(e), "critical": False}],
                )

    async def phase_3_authenticated_analysis(self) -> None:
        """Phase 3: Authenticated State Analysis (IDOR detection)."""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting Phase 3: Authenticated Analysis",
            phase="phase_3",
        )

        try:
            if not self.session_tokens.get("session_a") or not self.session_tokens.get(
                "session_b"
            ):
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    "Phase 3 skipped: No session tokens provided",
                    phase="phase_3",
                )
                self.manifest.update_phase(
                    "phase_3", "skipped", [{"reason": "No session tokens"}]
                )
                return

            endpoints = self.manifest.data["context_tree"].get("api_endpoints", [])
            base_url = f"https://{self.target}"

            handler = DualSessionHandler(base_url)
            idor_results = await handler.crawl_with_dual_sessions(
                self.session_tokens["session_a"],
                self.session_tokens["session_b"],
                endpoints,
            )

            self.manifest.add_context(
                "idor_targets", idor_results.get("idor_candidates", [])
            )
            self.manifest.update_phase(
                "phase_3", "completed", idor_results.get("idor_candidates", [])
            )

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f'Phase 3 Complete: {idor_results.get("total_candidates", 0)} IDOR candidates',
                phase="phase_3",
            )
        except Exception as e:
            # Determine if this is a critical error that should halt the pipeline
            critical_errors = (ConnectionError, TimeoutError, OSError)
            if isinstance(e, critical_errors):
                # Critical error - halt pipeline
                await self.ws_manager.send_log(
                    self.session_id,
                    "error",
                    f"Phase 3 critical failure: {str(e)}",
                    phase="phase_3",
                )
                self.manifest.update_phase(
                    "phase_3", "failed", [{"error": str(e), "critical": True}]
                )
                raise  # Re-raise to halt pipeline
            else:
                # Non-critical error - log but continue
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    f"Phase 3 non-critical error: {str(e)}",
                    phase="phase_3",
                )
                self.manifest.update_phase(
                    "phase_3",
                    "completed_with_warnings",
                    [{"error": str(e), "critical": False}],
                )

    async def phase_4_vulnerability_strikes(self) -> None:
        """Phase 4: Vulnerability-Specific Tactical Strikes."""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting Phase 4: Tactical Strikes",
            phase="phase_4",
        )

        try:
            orchestrator = TacticalStrikesOrchestrator(self.ai_router)

            endpoints = self.manifest.data["context_tree"].get("api_endpoints", [])
            tech_stack = self.manifest.data["context_tree"].get("tech_stack", {})

            # Execute all strike vectors
            idor_findings = await orchestrator.execute_bac_idor_strikes(
                endpoints, self.session_tokens.get("session_a", "")
            )
            ssrf_findings = await orchestrator.execute_ssrf_strikes(
                endpoints, tech_stack
            )
            bl_findings = await orchestrator.execute_business_logic_strikes(endpoints)

            all_strike_findings = idor_findings + ssrf_findings + bl_findings
            self.manifest.add_context("vulnerability_findings", all_strike_findings)
            self.manifest.update_phase(
                "phase_4",
                "completed",
                {
                    "idor_findings": len(idor_findings),
                    "ssrf_findings": len(ssrf_findings),
                    "business_logic_findings": len(bl_findings),
                    "total": len(all_strike_findings),
                },
            )

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Phase 4 Complete: {len(all_strike_findings)} vulnerability findings from tactical strikes",
                phase="phase_4",
            )
        except Exception as e:
            # Determine if this is a critical error that should halt the pipeline
            critical_errors = (ConnectionError, TimeoutError, OSError)
            if isinstance(e, critical_errors):
                # Critical error - halt pipeline
                await self.ws_manager.send_log(
                    self.session_id,
                    "error",
                    f"Phase 4 critical failure: {str(e)}",
                    phase="phase_4",
                )
                self.manifest.update_phase(
                    "phase_4", "failed", [{"error": str(e), "critical": True}]
                )
                raise  # Re-raise to halt pipeline
            else:
                # Non-critical error - log but continue
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    f"Phase 4 non-critical error: {str(e)}",
                    phase="phase_4",
                )
                self.manifest.update_phase(
                    "phase_4",
                    "completed_with_warnings",
                    [{"error": str(e), "critical": False}],
                )

    async def phase_5_advanced_injection(self) -> None:
        """Phase 5: Advanced Injection Testing (GraphQL & Prompt)."""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting Phase 5: Advanced Injection",
            phase="phase_5",
        )

        try:
            orchestrator = AdvancedInjectionOrchestrator(self.ai_router)

            endpoints = self.manifest.data["context_tree"].get("api_endpoints", [])
            tech_stack = self.manifest.data["context_tree"].get("tech_stack", {})

            # GraphQL attacks
            graphql_endpoints = [ep for ep in endpoints if ep.get("type") == "GraphQL"]
            graphql_findings = await orchestrator.execute_graphql_strikes(
                graphql_endpoints
            )

            # Prompt injection attacks
            prompt_findings = await orchestrator.execute_prompt_injection_strikes(
                endpoints, tech_stack
            )

            # General injection attacks
            injection_findings = await orchestrator.execute_injection_strikes(
                endpoints, tech_stack
            )

            all_injection_findings = (
                graphql_findings + prompt_findings + injection_findings
            )
            self.manifest.add_context("vulnerability_findings", all_injection_findings)

            self.manifest.update_phase(
                "phase_5",
                "completed",
                {
                    "graphql_findings": len(graphql_findings),
                    "prompt_injection_findings": len(prompt_findings),
                    "injection_findings": len(injection_findings),
                    "total": len(all_injection_findings),
                },
            )

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Phase 5 Complete: {len(all_injection_findings)} injection vulnerabilities found",
                phase="phase_5",
            )
        except Exception as e:
            # Determine if this is a critical error that should halt the pipeline
            critical_errors = (ConnectionError, TimeoutError, OSError)
            if isinstance(e, critical_errors):
                # Critical error - halt pipeline
                await self.ws_manager.send_log(
                    self.session_id,
                    "error",
                    f"Phase 5 critical failure: {str(e)}",
                    phase="phase_5",
                )
                self.manifest.update_phase(
                    "phase_5", "failed", [{"error": str(e), "critical": True}]
                )
                raise  # Re-raise to halt pipeline
            else:
                # Non-critical error - log but continue
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    f"Phase 5 non-critical error: {str(e)}",
                    phase="phase_5",
                )
                self.manifest.update_phase(
                    "phase_5",
                    "completed_with_warnings",
                    [{"error": str(e), "critical": False}],
                )

    async def phase_6_poc_generation(self) -> None:
        """Phase 6: Automated PoC Generation."""
        await self.ws_manager.send_log(
            self.session_id, "info", "Starting Phase 6: PoC Generation", phase="phase_6"
        )

        try:
            findings = self.manifest.data["context_tree"].get(
                "vulnerability_findings", []
            )
            pocs = []

            # Apply sampling if needed
            if len(findings) > POC_GENERATION_LIMIT:
                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"Generating PoCs for {POC_GENERATION_LIMIT} findings from {len(findings)} total",
                    phase="phase_6",
                )

            for finding in findings[:POC_GENERATION_LIMIT]:
                poc = await self.poc_generator.generate_poc(
                    finding.get("type", "generic"),
                    finding.get("endpoint", "/"),
                    finding.get("payload", {}),
                    self.session_tokens.get("session_a", ""),
                    f"https://{self.target}",
                )
                pocs.append(poc)

            self.manifest.add_context("pocs", pocs)
            self.manifest.update_phase(
                "phase_6", "completed", [{"pocs_generated": len(pocs)}]
            )

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Phase 6 Complete: {len(pocs)} PoCs generated",
                phase="phase_6",
            )
        except Exception as e:
            # Determine if this is a critical error that should halt the pipeline
            critical_errors = (ConnectionError, TimeoutError, OSError)
            if isinstance(e, critical_errors):
                # Critical error - halt pipeline
                await self.ws_manager.send_log(
                    self.session_id,
                    "error",
                    f"Phase 6 critical failure: {str(e)}",
                    phase="phase_6",
                )
                self.manifest.update_phase(
                    "phase_6", "failed", [{"error": str(e), "critical": True}]
                )
                raise  # Re-raise to halt pipeline
            else:
                # Non-critical error - log but continue
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    f"Phase 6 non-critical error: {str(e)}",
                    phase="phase_6",
                )
                self.manifest.update_phase(
                    "phase_6",
                    "completed_with_warnings",
                    [{"error": str(e), "critical": False}],
                )

    async def phase_7_reporting(self) -> None:
        """Phase 7: Adaptive Reporting."""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting Phase 7: Report Generation",
            phase="phase_7",
        )

        try:
            # Generate Markdown report
            all_findings = {
                "cves": self.manifest.data["context_tree"].get("cve_findings", []),
                "idor": self.manifest.data["context_tree"].get("idor_targets", []),
                "pocs": self.manifest.data["context_tree"].get("pocs", []),
            }

            report = self.report_generator.generate_report(
                self.target, all_findings, self.manifest.data
            )

            self.manifest.update_phase(
                "phase_7", "completed", [{"report_generated": True}]
            )

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                "Phase 7 Complete: Markdown report generated",
                phase="phase_7",
            )
        except Exception as e:
            # Phase 7 is report generation - always non-critical
            await self.ws_manager.send_log(
                self.session_id,
                "warning",
                f"Phase 7 report generation error: {str(e)}",
                phase="phase_7",
            )
            self.manifest.update_phase(
                "phase_7",
                "completed_with_warnings",
                [{"error": str(e), "critical": False}],
            )

    async def _check_port(self, host: str, port: str) -> bool:
        """Check if a port is open on a host using socket connection."""
        try:
            port_int = int(port)
            # Use asyncio to avoid blocking the event loop
            loop = asyncio.get_event_loop()

            def check_connection():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # 3 second timeout
                try:
                    result = sock.connect_ex((host, port_int))
                    return result == 0  # 0 means connection successful
                finally:
                    sock.close()

            return await loop.run_in_executor(None, check_connection)
        except (ValueError, Exception):
            return False
