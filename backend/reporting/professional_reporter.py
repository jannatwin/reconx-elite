"""
Professional Reporter - Phase 6 of Agentic Multi-Model Vulnerability Research Engine
Generates professional vulnerability reports with CVSS 4.0 scoring and functional curl commands
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

from ai_router import AIRouter
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityReport:
    vulnerability_id: str
    title: str
    severity: str  # P1-P5
    cvss_score: float
    cvss_vector: str
    endpoint: str
    method: str
    payload: str
    curl_command: str
    description: str
    impact_statement: str
    reproduction_steps: List[str]
    remediation_steps: List[str]
    references: List[str]
    confidence: float
    discovered_at: str


@dataclass
class ExecutiveSummary:
    target: str
    scan_date: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    cvss_average: float
    business_impact: str
    key_findings: List[str]
    recommendations: List[str]


class ProfessionalReporter:
    """Professional vulnerability reporting with CVSS 4.0 and curl commands"""

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager

        # Storage for reports
        self.vulnerability_reports: List[VulnerabilityReport] = []
        self.executive_summary: Optional[ExecutiveSummary] = None

        # CVSS 4.0 metrics
        self.cvss_metrics = {
            "attack_vector": {
                "network": 0.85,
                "adjacent": 0.62,
                "local": 0.55,
                "physical": 0.2,
            },
            "attack_complexity": {"low": 0.85, "high": 0.44},
            "privileges_required": {"none": 0.85, "low": 0.62, "high": 0.5},
            "user_interaction": {"none": 0.85, "required": 0.62},
            "scope": {"unchanged": 1.0, "changed": 1.5},
            "confidentiality": {"high": 0.56, "low": 0.22, "none": 0.0},
            "integrity": {"high": 0.56, "low": 0.22, "none": 0.0},
            "availability": {"high": 0.56, "low": 0.22, "none": 0.0},
        }

        # Severity to P-level mapping
        self.severity_mapping = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4",
            "info": "P5",
        }

    async def execute(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute professional reporting process"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting professional vulnerability reporting...",
            phase="professional_reporting",
        )

        try:
            # Phase 6.1: Process vulnerability findings
            await self._process_vulnerability_findings(scan_results)

            # Phase 6.2: Generate curl commands
            await self._generate_curl_commands()

            # Phase 6.3: Calculate CVSS 4.0 scores
            await self._calculate_cvss_scores()

            # Phase 6.4: Generate detailed reports
            await self._generate_detailed_reports()

            # Phase 6.5: Create executive summary
            await self._create_executive_summary()

            # Phase 6.6: Generate Nuclei templates
            await self._generate_nuclei_templates()

            # Phase 6.7: Generate markdown report
            markdown_report = await self._generate_markdown_report()

            # Save report to file
            await self._save_report_to_file(markdown_report)

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Professional reporting completed: {len(self.vulnerability_reports)} vulnerabilities reported",
                phase="professional_reporting",
            )

            return {
                "vulnerability_reports": [
                    asdict(report) for report in self.vulnerability_reports
                ],
                "executive_summary": (
                    asdict(self.executive_summary) if self.executive_summary else None
                ),
                "markdown_report": markdown_report,
            }

        except Exception as e:
            logger.error(f"Professional reporting failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Professional reporting failed: {str(e)}",
                phase="professional_reporting",
            )
            raise

    async def _process_vulnerability_findings(
        self, scan_results: Dict[str, Any]
    ) -> None:
        """Process vulnerability findings from scan results"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Processing vulnerability findings...",
            phase="findings_processing",
        )

        # Extract findings from all modules
        all_findings = []

        # Process Big 7 vulnerability modules
        modules = [
            "bac_idor",
            "injection",
            "ssrf_misconfig",
            "xss_bypass",
            "auth_session",
            "business_logic",
        ]

        for module in modules:
            module_results = scan_results.get(module, {})
            findings = module_results.get("findings", []) or module_results.get(
                "results", []
            )

            for finding in findings:
                if isinstance(finding, dict):
                    all_findings.append({**finding, "module": module})

        # Process predictive sandbox results
        sandbox_results = scan_results.get("predictive_sandbox", {})
        sandbox_tests = sandbox_results.get("sandbox_tests", {}).get("results", [])

        for test in sandbox_tests:
            if isinstance(test, dict) and test.get("test_result", "").startswith(
                "success"
            ):
                all_findings.append(
                    {
                        **test,
                        "module": "predictive_sandbox",
                        "vulnerability_type": test.get("vulnerability_type", "unknown"),
                    }
                )

        # Create vulnerability reports
        for i, finding in enumerate(all_findings):
            try:
                report = await self._create_vulnerability_report(finding, i)
                self.vulnerability_reports.append(report)

            except Exception as e:
                logger.debug(f"Failed to process finding {i}: {e}")

    async def _create_vulnerability_report(
        self, finding: Dict[str, Any], index: int
    ) -> VulnerabilityReport:
        """Create a vulnerability report from a finding"""
        vulnerability_id = f"VULN-{datetime.now().strftime('%Y%m%d')}-{index + 1:03d}"

        # Extract basic information
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET")
        payload = finding.get("payload", {})
        vuln_type = finding.get("vulnerability_type", "Unknown")
        confidence = finding.get("confidence", 0.5)

        # Generate title
        title = f"{vuln_type} in {endpoint}"

        # Set initial severity (will be updated with CVSS)
        severity = self._map_confidence_to_severity(confidence)

        # Generate description
        description = await self._generate_description(finding)

        # Generate impact statement
        impact_statement = await self._generate_impact_statement(vuln_type, finding)

        # Generate reproduction steps
        reproduction_steps = await self._generate_reproduction_steps(finding)

        # Generate remediation steps
        remediation_steps = await self._generate_remediation_steps(vuln_type, finding)

        # Generate references
        references = await self._generate_references(vuln_type)

        return VulnerabilityReport(
            vulnerability_id=vulnerability_id,
            title=title,
            severity=severity,
            cvss_score=0.0,  # Will be calculated
            cvss_vector="",  # Will be calculated
            endpoint=endpoint,
            method=method,
            payload=str(payload),
            curl_command="",  # Will be generated
            description=description,
            impact_statement=impact_statement,
            reproduction_steps=reproduction_steps,
            remediation_steps=remediation_steps,
            references=references,
            confidence=confidence,
            discovered_at=datetime.now().isoformat(),
        )

    def _map_confidence_to_severity(self, confidence: float) -> str:
        """Map confidence to severity level"""
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"

    async def _generate_description(self, finding: Dict[str, Any]) -> str:
        """Generate vulnerability description using AI"""
        vuln_type = finding.get("vulnerability_type", "Unknown")
        endpoint = finding.get("endpoint", "")
        module = finding.get("module", "unknown")

        prompt = f"""
        Generate a professional vulnerability description for:
        
        Vulnerability Type: {vuln_type}
        Endpoint: {endpoint}
        Module: {module}
        
        Include:
        1. What the vulnerability is
        2. Where it was found
        3. Why it's a security issue
        4. Technical details
        
        Keep it professional and technical (150-200 words).
        """

        try:
            result = await self.ai_router.call_model(
                role="deep_analyst",
                prompt=prompt,
                max_tokens=300,
                task_type="report_generation",
            )

            if result.get("output"):
                return result["output"].strip()

        except Exception as e:
            logger.error(f"AI description generation failed: {e}")

        # Fallback description
        return f"A {vuln_type} vulnerability was identified in the endpoint {endpoint}. This security issue could potentially allow attackers to exploit the affected system and should be remediated promptly."

    async def _generate_impact_statement(
        self, vuln_type: str, finding: Dict[str, Any]
    ) -> str:
        """Generate impact statement"""
        impact_templates = {
            "sql injection": "Full database compromise possible with unauthorized data access, modification, and potential complete system takeover.",
            "command injection": "Remote code execution possible leading to full system compromise, data exfiltration, and lateral movement.",
            "xss": "Cross-site scripting allows session hijacking, credential theft, and potential account takeover.",
            "ssrf": "Server-side request forgery enables access to internal services, cloud metadata, and potential network pivoting.",
            "idor": "Insecure direct object reference allows unauthorized access to other users' data and potential account takeover.",
            "auth bypass": "Authentication bypass enables complete account takeover and unauthorized system access.",
            "business logic": "Business logic flaws allow financial manipulation, unauthorized actions, and potential fraud.",
        }

        vuln_type_lower = vuln_type.lower()

        for key, impact in impact_templates.items():
            if key in vuln_type_lower:
                return impact

        return "Security vulnerability allows unauthorized access and potential system compromise."

    async def _generate_reproduction_steps(self, finding: Dict[str, Any]) -> List[str]:
        """Generate step-by-step reproduction instructions"""
        steps = [
            "1. Identify the vulnerable endpoint",
            f"2. Prepare the malicious payload: {finding.get('payload', {})}",
            f"3. Send {finding.get('method', 'GET')} request to {finding.get('endpoint', '')}",
            "4. Observe the response indicating successful exploitation",
            "5. Verify the vulnerability impact",
        ]

        return steps

    async def _generate_remediation_steps(
        self, vuln_type: str, finding: Dict[str, Any]
    ) -> List[str]:
        """Generate remediation steps"""
        remediation_templates = {
            "sql injection": [
                "Implement parameterized queries/prepared statements",
                "Use input validation and sanitization",
                "Apply principle of least privilege to database accounts",
                "Enable database query logging and monitoring",
            ],
            "command injection": [
                "Avoid shell command construction with user input",
                "Use allow-lists for validated commands",
                "Implement proper input validation and encoding",
                "Use secure APIs instead of system calls",
            ],
            "xss": [
                "Implement Content Security Policy (CSP)",
                "Use output encoding and contextual escaping",
                "Validate and sanitize all user inputs",
                "Use secure frameworks with built-in XSS protection",
            ],
            "ssrf": [
                "Validate and whitelist all URLs",
                "Disable unnecessary URL schemes",
                "Implement network-level restrictions",
                "Use dedicated HTTP client libraries with security controls",
            ],
            "idor": [
                "Implement proper authorization checks",
                "Use indirect references instead of direct IDs",
                "Validate user permissions for all resource access",
                "Implement access control lists (ACLs)",
            ],
            "auth bypass": [
                "Implement multi-factor authentication",
                "Use secure session management",
                "Validate all authentication tokens",
                "Implement proper account lockout mechanisms",
            ],
        }

        vuln_type_lower = vuln_type.lower()

        for key, steps in remediation_templates.items():
            if key in vuln_type_lower:
                return steps

        return [
            "Implement proper input validation",
            "Add security controls and monitoring",
            "Conduct security testing",
            "Update security policies",
        ]

    async def _generate_references(self, vuln_type: str) -> List[str]:
        """Generate reference links"""
        base_references = [
            "https://owasp.org/",
            "https://cwe.mitre.org/",
            "https://portswigger.net/web-security/",
        ]

        vuln_specific = {
            "sql injection": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            "xss": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            "ssrf": [
                "https://owasp.org/www-community/vulnerabilities/Server_Side_Request_Forgery",
                "https://cwe.mitre.org/data/definitions/918.html",
            ],
        }

        vuln_type_lower = vuln_type.lower()

        for key, refs in vuln_specific.items():
            if key in vuln_type_lower:
                return refs + base_references

        return base_references

    async def _generate_curl_commands(self) -> None:
        """Generate functional curl commands for all vulnerabilities"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating curl commands...",
            phase="curl_generation",
        )

        for report in self.vulnerability_reports:
            try:
                curl_command = self._build_curl_command(report)
                report.curl_command = curl_command
            except Exception as e:
                logger.debug(
                    f"Failed to generate curl command for {report.vulnerability_id}: {e}"
                )
                report.curl_command = "# Failed to generate curl command"

    def _build_curl_command(self, report: VulnerabilityReport) -> str:
        """Build functional curl command"""
        # Base curl command
        curl_parts = ["curl"]

        # Add method
        if report.method.upper() != "GET":
            curl_parts.append(f"-X {report.method}")

        # Add headers
        headers = []
        headers.append("Content-Type: application/json")
        headers.append("User-Agent: ReconX-Elite/1.0")

        # Add authentication headers if needed
        if "auth" in report.endpoint.lower() or "admin" in report.endpoint.lower():
            headers.append("Authorization: Bearer <TOKEN>")

        for header in headers:
            curl_parts.append(f"-H '{header}'")

        # Add payload/data
        if report.payload and report.payload != "{}":
            if report.method.upper() == "GET":
                # For GET, add as query parameters
                curl_parts.append(f"-G")
                curl_parts.append(f"-d '{report.payload}'")
            else:
                # For POST/PUT, add as data
                curl_parts.append(f"-d '{report.payload}'")

        # Add URL
        curl_parts.append(f"'{report.endpoint}'")

        # Add options
        curl_parts.extend(
            [
                "-k",  # Allow insecure connections
                "-i",  # Include headers
                "-v",  # Verbose
                "--connect-timeout 30",
                "--max-time 60",
            ]
        )

        return " ".join(curl_parts)

    async def _calculate_cvss_scores(self) -> None:
        """Calculate CVSS 4.0 scores for all vulnerabilities"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Calculating CVSS 4.0 scores...",
            phase="cvss_scoring",
        )

        for report in self.vulnerability_reports:
            try:
                cvss_score, cvss_vector = await self._calculate_cvss_40(report)
                report.cvss_score = cvss_score
                report.cvss_vector = cvss_vector

                # Update severity based on CVSS score
                report.severity = self._cvss_score_to_severity(cvss_score)
                report.severity = self.severity_mapping.get(report.severity, "P5")

            except Exception as e:
                logger.debug(
                    f"Failed to calculate CVSS for {report.vulnerability_id}: {e}"
                )
                report.cvss_score = 5.0
                report.cvss_vector = "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

    async def _calculate_cvss_40(
        self, report: VulnerabilityReport
    ) -> Tuple[float, str]:
        """Calculate CVSS 4.0 score and vector"""
        vuln_type = report.vulnerability_type.lower()

        # Base score metrics
        av = "AV:N"  # Network
        ac = "AC:L"  # Low complexity
        pr = "PR:N"  # No privileges required
        ui = "UI:N"  # No user interaction
        s = "S:U"  # Scope unchanged

        # Impact metrics based on vulnerability type
        if "sql injection" in vuln_type or "command injection" in vuln_type:
            c, i, a = "C:H", "I:H", "A:H"  # High impact
        elif "xss" in vuln_type or "ssrf" in vuln_type:
            c, i, a = "C:H", "I:L", "A:N"  # High confidentiality, low integrity
        elif "idor" in vuln_type or "auth" in vuln_type:
            c, i, a = "C:H", "I:H", "A:N"  # High confidentiality and integrity
        elif "business logic" in vuln_type:
            c, i, a = "C:N", "I:H", "A:N"  # High integrity impact
        else:
            c, i, a = "C:L", "I:L", "A:L"  # Low impact

        # Build CVSS vector
        cvss_vector = f"CVSS:4.0/{av}/{ac}/{pr}/{ui}/{s}/{c}/{i}/{a}"

        # Calculate base score (simplified CVSS 4.0 calculation)
        # This is a simplified version - full CVSS 4.0 calculation is more complex
        base_score = self._calculate_base_score(av, ac, pr, ui, s, c, i, a)

        return base_score, cvss_vector

    def _calculate_base_score(
        self, av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
    ) -> float:
        """Simplified CVSS 4.0 base score calculation"""
        # Extract metric values
        av_val = self.cvss_metrics["attack_vector"].get(av.split(":")[1], 0.85)
        ac_val = self.cvss_metrics["attack_complexity"].get(ac.split(":")[1], 0.85)
        pr_val = self.cvss_metrics["privileges_required"].get(pr.split(":")[1], 0.85)
        ui_val = self.cvss_metrics["user_interaction"].get(ui.split(":")[1], 0.85)
        s_val = self.cvss_metrics["scope"].get(s.split(":")[1], 1.0)

        c_val = self.cvss_metrics["confidentiality"].get(c.split(":")[1], 0.0)
        i_val = self.cvss_metrics["integrity"].get(i.split(":")[1], 0.0)
        a_val = self.cvss_metrics["availability"].get(a.split(":")[1], 0.0)

        # Simplified calculation
        exploitability = av_val * ac_val * pr_val * ui_val
        impact = (c_val + i_val + a_val) / 3.0

        base_score = exploitability * impact * s_val

        # Scale to 0-10 range
        return min(max(base_score * 10, 0.0), 10.0)

    def _cvss_score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity"""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"

    async def _generate_detailed_reports(self) -> None:
        """Enhance reports with AI-generated details"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating detailed reports...",
            phase="detailed_reports",
        )

        for report in self.vulnerability_reports:
            try:
                # Enhance description with AI
                enhanced_description = await self._enhance_description_with_ai(report)
                if enhanced_description:
                    report.description = enhanced_description

                # Generate additional impact analysis
                impact_analysis = await self._generate_impact_analysis(report)
                if impact_analysis:
                    report.impact_statement += f"\n\n{impact_analysis}"

            except Exception as e:
                logger.debug(f"Failed to enhance report {report.vulnerability_id}: {e}")

    async def _enhance_description_with_ai(
        self, report: VulnerabilityReport
    ) -> Optional[str]:
        """Enhance description with AI analysis"""
        prompt = f"""
        Enhance this vulnerability description with technical details:
        
        Current Description: {report.description}
        Vulnerability Type: {report.vulnerability_type}
        Endpoint: {report.endpoint}
        CVSS Score: {report.cvss_score}
        
        Add:
        1. Technical explanation of the vulnerability
        2. Attack scenarios
        3. Affected components
        4. Business context
        
        Keep it professional and detailed (200-300 words).
        """

        try:
            result = await self.ai_router.call_model(
                role="gpt-oss-120b",  # Use high-end model for reporting
                prompt=prompt,
                max_tokens=500,
                task_type="report_generation",
            )

            if result.get("output"):
                return result["output"].strip()

        except Exception as e:
            logger.error(f"AI description enhancement failed: {e}")

        return None

    async def _generate_impact_analysis(
        self, report: VulnerabilityReport
    ) -> Optional[str]:
        """Generate detailed impact analysis"""
        prompt = f"""
        Generate a detailed impact analysis for:
        
        Vulnerability: {report.vulnerability_type}
        Target: {self.target}
        CVSS Score: {report.cvss_score}
        
        Include:
        1. Technical impact
        2. Business impact
        3. Compliance implications
        4. Data at risk
        
        Keep it professional (100-150 words).
        """

        try:
            result = await self.ai_router.call_model(
                role="gpt-oss-120b",
                prompt=prompt,
                max_tokens=300,
                task_type="report_generation",
            )

            if result.get("output"):
                return result["output"].strip()

        except Exception as e:
            logger.error(f"AI impact analysis failed: {e}")

        return None

    async def _create_executive_summary(self) -> None:
        """Create executive summary"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Creating executive summary...",
            phase="executive_summary",
        )

        total_vulns = len(self.vulnerability_reports)
        critical_count = len(
            [r for r in self.vulnerability_reports if "P1" in r.severity]
        )
        high_count = len([r for r in self.vulnerability_reports if "P2" in r.severity])
        medium_count = len(
            [r for r in self.vulnerability_reports if "P3" in r.severity]
        )
        low_count = len([r for r in self.vulnerability_reports if "P4" in r.severity])

        avg_cvss = sum(r.cvss_score for r in self.vulnerability_reports) / max(
            total_vulns, 1
        )

        # Generate business impact
        business_impact = await self._generate_business_impact()

        # Generate key findings
        key_findings = [
            f"{critical_count} Critical (P1) vulnerabilities requiring immediate attention",
            f"{high_count} High (P2) vulnerabilities that should be addressed within 30 days",
            f"Average CVSS score of {avg_cvss:.1f} indicates significant risk exposure",
        ]

        # Generate recommendations
        recommendations = [
            "Immediately address all Critical (P1) vulnerabilities",
            "Implement a remediation plan for High (P2) findings",
            "Establish regular security testing schedule",
            "Enhance security monitoring and incident response",
        ]

        self.executive_summary = ExecutiveSummary(
            target=self.target,
            scan_date=datetime.now().strftime("%Y-%m-%d"),
            total_vulnerabilities=total_vulns,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            cvss_average=avg_cvss,
            business_impact=business_impact,
            key_findings=key_findings,
            recommendations=recommendations,
        )

    async def _generate_business_impact(self) -> str:
        """Generate business impact statement"""
        critical_count = len(
            [r for r in self.vulnerability_reports if "P1" in r.severity]
        )
        high_count = len([r for r in self.vulnerability_reports if "P2" in r.severity])

        if critical_count > 0:
            return "Critical vulnerabilities present immediate risk to business continuity and data security. Immediate remediation is required to prevent potential security breaches."
        elif high_count > 0:
            return "High-severity vulnerabilities pose significant risk to sensitive data and system integrity. Prompt remediation is necessary to maintain security posture."
        else:
            return "Security posture is moderate with room for improvement. Addressing identified vulnerabilities will enhance overall security."

    async def _generate_markdown_report(self) -> str:
        """Generate comprehensive markdown report"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating markdown report...",
            phase="markdown_generation",
        )

        # Build markdown sections
        sections = []

        # Title and metadata
        sections.append(f"# Vulnerability Assessment Report")
        sections.append(f"**Target:** {self.target}")
        sections.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}")
        sections.append(f"**Assessment ID:** {self.session_id}")
        sections.append("")

        # Executive summary
        if self.executive_summary:
            sections.append("## Executive Summary")
            sections.append("")
            sections.append(
                f"**Total Vulnerabilities:** {self.executive_summary.total_vulnerabilities}"
            )
            sections.append(
                f"**Critical (P1):** {self.executive_summary.critical_count}"
            )
            sections.append(f"**High (P2):** {self.executive_summary.high_count}")
            sections.append(f"**Medium (P3):** {self.executive_summary.medium_count}")
            sections.append(f"**Low (P4):** {self.executive_summary.low_count}")
            sections.append(
                f"**Average CVSS Score:** {self.executive_summary.cvss_average:.1f}"
            )
            sections.append("")
            sections.append("### Business Impact")
            sections.append(self.executive_summary.business_impact)
            sections.append("")
            sections.append("### Key Findings")
            for finding in self.executive_summary.key_findings:
                sections.append(f"- {finding}")
            sections.append("")
            sections.append("### Recommendations")
            for rec in self.executive_summary.recommendations:
                sections.append(f"- {rec}")
            sections.append("")

        # Detailed findings
        sections.append("## Detailed Vulnerability Findings")
        sections.append("")

        # Group by severity
        severity_groups = {}
        for report in self.vulnerability_reports:
            severity = report.severity
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(report)

        for severity in ["P1", "P2", "P3", "P4", "P5"]:
            if severity in severity_groups:
                sections.append(f"### {severity} Vulnerabilities")
                sections.append("")

                for report in severity_groups[severity]:
                    sections.append(f"#### {report.title}")
                    sections.append("")
                    sections.append(f"**Vulnerability ID:** {report.vulnerability_id}")
                    sections.append(
                        f"**CVSS Score:** {report.cvss_score:.1f} ({report.cvss_vector})"
                    )
                    sections.append(f"**Endpoint:** {report.endpoint}")
                    sections.append(f"**Method:** {report.method}")
                    sections.append(f"**Confidence:** {report.confidence:.2f}")
                    sections.append("")

                    sections.append("**Description:**")
                    sections.append(report.description)
                    sections.append("")

                    sections.append("**Impact:**")
                    sections.append(report.impact_statement)
                    sections.append("")

                    sections.append("**Reproduction Steps:**")
                    for step in report.reproduction_steps:
                        sections.append(f"{step}")
                    sections.append("")

                    sections.append("**Curl Command:**")
                    sections.append("```bash")
                    sections.append(report.curl_command)
                    sections.append("```")
                    sections.append("")

                    sections.append("**Remediation:**")
                    for step in report.remediation_steps:
                        sections.append(f"{step}")
                    sections.append("")

                    sections.append("**References:**")
                    for ref in report.references:
                        sections.append(f"- {ref}")
                    sections.append("")
                    sections.append("---")
                    sections.append("")

        # Appendices
        sections.append("## Appendices")
        sections.append("")
        sections.append("### Assessment Methodology")
        sections.append(
            "This assessment was conducted using ReconX-Elite, an autonomous vulnerability research engine that combines AI-driven analysis with comprehensive security testing."
        )
        sections.append("")
        sections.append("### Severity Classification")
        sections.append(
            "- **P1 (Critical):** Immediate threat requiring emergency remediation"
        )
        sections.append(
            "- **P2 (High):** Significant risk requiring prompt remediation"
        )
        sections.append(
            "- **P3 (Medium):** Moderate risk requiring scheduled remediation"
        )
        sections.append("- **P4 (Low):** Minor risk requiring routine remediation")
        sections.append(
            "- **P5 (Informational):** Security best practice recommendations"
        )
        sections.append("")

        return "\n".join(sections)

    async def _save_report_to_file(self, markdown_report: str) -> None:
        """Save report to file"""
        try:
            # Create reports directory if it doesn't exist
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{self.target.replace('.', '_')}_{timestamp}.md"
            filepath = reports_dir / filename

            # Write report
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(markdown_report)

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Report saved to {filepath}",
                phase="report_saving",
            )

        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "warning",
                f"Failed to save report: {str(e)}",
                phase="report_saving",
            )

    async def _generate_nuclei_templates(self) -> None:
        """Generate Nuclei templates for high-confidence vulnerabilities"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating Nuclei templates...",
            phase="nuclei_generation",
        )

        # Filter high-confidence vulnerabilities
        high_confidence_reports = [
            report for report in self.vulnerability_reports if report.confidence > 0.9
        ]

        if not high_confidence_reports:
            await self.ws_manager.send_log(
                self.session_id,
                "info",
                "No high-confidence vulnerabilities for Nuclei template generation",
                phase="nuclei_generation",
            )
            return

        # Create templates directory
        templates_dir = Path("templates/custom")
        templates_dir.mkdir(parents=True, exist_ok=True)

        # Generate templates
        for report in high_confidence_reports:
            try:
                template = await self._generate_single_nuclei_template(report)
                if template:
                    await self._save_nuclei_template(template, templates_dir)
            except Exception as e:
                logger.debug(
                    f"Failed to generate Nuclei template for {report.vulnerability_id}: {e}"
                )

        await self.ws_manager.send_log(
            self.session_id,
            "success",
            f"Generated {len(high_confidence_reports)} Nuclei templates",
            phase="nuclei_generation",
        )

    async def _generate_single_nuclei_template(
        self, report: VulnerabilityReport
    ) -> Optional[str]:
        """Generate a single Nuclei template for a vulnerability"""
        prompt = f"""
        Generate a Nuclei YAML template for the following vulnerability:
        
        Target: {self.target}
        Vulnerability ID: {report.vulnerability_id}
        Title: {report.title}
        Severity: {report.severity}
        CVSS Score: {report.cvss_score}
        Endpoint: {report.endpoint}
        Method: {report.method}
        Payload: {report.payload}
        Description: {report.description}
        
        Generate a valid Nuclei template with:
        1. Proper YAML structure
        2. ID, name, severity, and classification
        3. HTTP request matcher with the payload
        4. Extractors for vulnerability confirmation
        5. Metadata including CWE reference and CVSS score
        
        Use the following format:
        id: reconx-{report.vulnerability_id.lower()}
        info:
          name: {report.title}
          author: ReconX-Elite
          severity: {report.severity.lower()}
          classification:
            cwe-id: CWE-79
            cvss-metrics: {report.cvss_vector}
            cvss-score: {report.cvss_score}
          tags: {report.vulnerability_type.lower()}
        
        requests:
          - method: {report.method.upper()}
            path: {report.endpoint}
            headers:
              Content-Type: application/json
            body: {report.payload}
            
            matchers:
              - type: word
                words:
                  - "success"
                part: body
            
            extractors:
              - type: regex
                regex:
                  - "vulnerability confirmed"
                part: body
        
        Return only the YAML template without any additional text.
        """

        try:
            result = await self.ai_router.call_model(
                role="code_engine",  # Use Qwen3 Coder 480B for template generation
                prompt=prompt,
                max_tokens=1000,
                task_type="template_generation",
            )

            if result.get("output"):
                return result["output"].strip()

        except Exception as e:
            logger.error(f"Nuclei template generation failed: {e}")

        return None

    async def _save_nuclei_template(self, template: str, templates_dir: Path) -> None:
        """Save Nuclei template to file"""
        try:
            # Extract template ID for filename
            template_id = "unknown"
            for line in template.split("\n"):
                if line.strip().startswith("id:"):
                    template_id = line.split(":", 1)[1].strip().strip('"')
                    break

            # Sanitize filename
            safe_filename = template_id.replace("/", "_").replace("\\", "_")
            template_file = templates_dir / f"{safe_filename}.yaml"

            # Save template
            with open(template_file, "w", encoding="utf-8") as f:
                f.write(template)

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Nuclei template saved: {template_file}",
                phase="nuclei_generation",
            )

        except Exception as e:
            logger.error(f"Failed to save Nuclei template: {e}")
