"""
Mass Scan Module - Rapid Response System
Parallel Nuclei template execution across multiple domains from baselines
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ai_router import AIRouter
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class MassScanTarget:
    domain: str
    baseline_file: str
    status: ScanStatus
    start_time: Optional[str]
    end_time: Optional[str]
    findings_count: int
    error_message: Optional[str]


@dataclass
class TemplateValidation:
    template_path: str
    is_valid: bool
    validation_errors: List[str]
    template_info: Dict[str, Any]


@dataclass
class ScanResult:
    target_domain: str
    template_path: str
    status: ScanStatus
    findings: List[Dict[str, Any]]
    execution_time: float
    error_message: Optional[str]


class MassScanner:
    """Mass scanning system for parallel Nuclei template execution"""

    def __init__(
        self,
        session_id: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
    ):
        self.session_id = session_id
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager

        # Storage for scan data
        self.targets: List[MassScanTarget] = []
        self.templates: List[TemplateValidation] = []
        self.scan_results: List[ScanResult] = []

        # Configuration
        self.max_concurrent_scans = int(os.getenv("MASS_SCAN_CONCURRENT_LIMIT", "10"))
        self.scan_timeout = int(os.getenv("MASS_SCAN_TIMEOUT", "300"))  # 5 minutes
        self.rate_limit_delay = float(os.getenv("MASS_SCAN_RATE_DELAY", "1.0"))

        # Baseline directory
        self.baseline_dir = Path("baselines")
        self.templates_dir = Path("templates")
        self.results_dir = Path("mass_scan_results")

        # Ensure directories exist
        self.results_dir.mkdir(exist_ok=True)

    async def execute(
        self, template_paths: List[str], domain_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute mass scan across all domains in baselines"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting mass scan execution...",
            phase="mass_scan",
        )

        try:
            # Phase 1: Validate templates
            await self._validate_templates(template_paths)

            # Phase 2: Extract targets from baselines
            await self._extract_targets(domain_filter)

            # Phase 3: Execute parallel scans
            await self._execute_parallel_scans()

            # Phase 4: Consolidate results
            await self._consolidate_results()

            # Phase 5: Generate reports
            await self._generate_reports()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Mass scan completed: {len(self.scan_results)} scans executed, {sum(r.findings_count for r in self.targets)} total findings",
                phase="mass_scan",
            )

            return results

        except Exception as e:
            logger.error(f"Mass scan execution failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Mass scan failed: {str(e)}",
                phase="mass_scan",
            )
            raise

    async def _validate_templates(self, template_paths: List[str]) -> None:
        """Validate Nuclei templates before scanning"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Validating {len(template_paths)} templates...",
            phase="mass_scan",
        )

        for template_path in template_paths:
            try:
                validation = await self._validate_single_template(template_path)
                self.templates.append(validation)

                if not validation.is_valid:
                    await self.ws_manager.send_log(
                        self.session_id,
                        "warning",
                        f'Template validation failed: {template_path} - {", ".join(validation.validation_errors)}',
                        phase="mass_scan",
                    )

            except Exception as e:
                logger.debug(f"Template validation failed for {template_path}: {e}")
                validation = TemplateValidation(
                    template_path=template_path,
                    is_valid=False,
                    validation_errors=[str(e)],
                    template_info={},
                )
                self.templates.append(validation)

        valid_templates = [t for t in self.templates if t.is_valid]
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Template validation completed: {len(valid_templates)}/{len(template_paths)} valid",
            phase="mass_scan",
        )

    async def _validate_single_template(self, template_path: str) -> TemplateValidation:
        """Validate a single Nuclei template"""
        try:
            # Check if template file exists
            template_file = Path(template_path)
            if not template_file.exists():
                return TemplateValidation(
                    template_path=template_path,
                    is_valid=False,
                    validation_errors=["Template file not found"],
                    template_info={},
                )

            # Read template content
            with open(template_file, "r") as f:
                template_content = f.read()

            # Basic YAML structure validation
            validation_errors = []
            template_info = {}

            # Check for required fields
            if "id:" not in template_content:
                validation_errors.append("Missing required field: id")

            if "info:" not in template_content:
                validation_errors.append("Missing required field: info")

            if "requests:" not in template_content:
                validation_errors.append("Missing required field: requests")

            # Extract template info
            try:
                lines = template_content.split("\n")
                for line in lines:
                    if line.strip().startswith("id:"):
                        template_info["id"] = line.split(":", 1)[1].strip()
                    elif line.strip().startswith("name:"):
                        template_info["name"] = line.split(":", 1)[1].strip()
                    elif line.strip().startswith("severity:"):
                        template_info["severity"] = line.split(":", 1)[1].strip()
            except Exception:
                pass

            # Try nuclei validation if available
            try:
                result = subprocess.run(
                    ["nuclei", "-validate", "-t", template_path],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode != 0:
                    validation_errors.append(
                        f"Nuclei validation failed: {result.stderr}"
                    )

            except (subprocess.TimeoutExpired, FileNotFoundError):
                # nuclei not available, skip validation
                pass

            return TemplateValidation(
                template_path=template_path,
                is_valid=len(validation_errors) == 0,
                validation_errors=validation_errors,
                template_info=template_info,
            )

        except Exception as e:
            return TemplateValidation(
                template_path=template_path,
                is_valid=False,
                validation_errors=[str(e)],
                template_info={},
            )

    async def _extract_targets(self, domain_filter: Optional[str] = None) -> None:
        """Extract target domains from baseline files"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Extracting targets from baseline files...",
            phase="mass_scan",
        )

        if not self.baseline_dir.exists():
            await self.ws_manager.send_log(
                self.session_id,
                "warning",
                "Baseline directory not found",
                phase="mass_scan",
            )
            return

        # Get all baseline files
        baseline_files = list(self.baseline_dir.glob("*_baseline.json"))

        for baseline_file in baseline_files:
            try:
                with open(baseline_file, "r") as f:
                    baseline_data = json.load(f)

                # Extract domain from filename
                domain = baseline_file.stem.replace("_baseline", "").replace("_", ".")

                # Apply domain filter if specified
                if domain_filter and domain_filter not in domain:
                    continue

                # Count subdomains in baseline
                subdomain_count = 0
                for path, entry in baseline_data.items():
                    if path.startswith("subdomain:"):
                        subdomain_count += 1

                target = MassScanTarget(
                    domain=domain,
                    baseline_file=str(baseline_file),
                    status=ScanStatus.PENDING,
                    start_time=None,
                    end_time=None,
                    findings_count=0,
                    error_message=None,
                )

                self.targets.append(target)

            except Exception as e:
                logger.debug(f"Failed to extract targets from {baseline_file}: {e}")

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Extracted {len(self.targets)} targets from baselines",
            phase="mass_scan",
        )

    async def _execute_parallel_scans(self) -> None:
        """Execute scans in parallel with rate limiting"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Executing parallel scans with {self.max_concurrent_scans} concurrent limit",
            phase="mass_scan",
        )

        # Get valid templates
        valid_templates = [t for t in self.templates if t.is_valid]
        if not valid_templates:
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                "No valid templates available for scanning",
                phase="mass_scan",
            )
            return

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent_scans)

        # Create scan tasks
        scan_tasks = []
        for target in self.targets:
            for template in valid_templates:
                task = self._scan_target_with_semaphore(semaphore, target, template)
                scan_tasks.append(task)

        # Execute all scans
        try:
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            # Process results
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Scan task failed: {result}")
                elif isinstance(result, ScanResult):
                    self.scan_results.append(result)
                    # Update target status
                    target = next(
                        (t for t in self.targets if t.domain == result.target_domain),
                        None,
                    )
                    if target:
                        target.status = result.status
                        target.findings_count = len(result.findings)
                        if result.error_message:
                            target.error_message = result.error_message

        except Exception as e:
            logger.error(f"Parallel scan execution failed: {e}")

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Parallel scans completed: {len(self.scan_results)} results",
            phase="mass_scan",
        )

    async def _scan_target_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        target: MassScanTarget,
        template: TemplateValidation,
    ) -> ScanResult:
        """Execute scan with semaphore control"""
        async with semaphore:
            return await self._scan_single_target(target, template)

    async def _scan_single_target(
        self, target: MassScanTarget, template: TemplateValidation
    ) -> ScanResult:
        """Execute Nuclei scan on a single target"""
        start_time = time.time()

        # Update target status
        target.status = ScanStatus.RUNNING
        target.start_time = datetime.now().isoformat()

        try:
            # Prepare nuclei command
            cmd = [
                "nuclei",
                "-t",
                template.template_path,
                "-u",
                f"https://{target.domain}",
                "-json",
                "-silent",
                "-timeout",
                str(self.scan_timeout),
                "-rate-limit",
                str(int(1 / self.rate_limit_delay)),
            ]

            # Execute nuclei
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.scan_timeout
            )

            execution_time = time.time() - start_time

            # Parse results
            findings = []
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            # Determine status
            if result.returncode == 0:
                status = ScanStatus.COMPLETED
            elif result.returncode == 124:  # Timeout
                status = ScanStatus.TIMEOUT
            else:
                status = ScanStatus.FAILED

            scan_result = ScanResult(
                target_domain=target.domain,
                template_path=template.template_path,
                status=status,
                findings=findings,
                execution_time=execution_time,
                error_message=result.stderr if result.returncode != 0 else None,
            )

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f'Scan completed: {target.domain} with {template.template_info.get("name", "unknown")} - {len(findings)} findings',
                phase="mass_scan",
            )

            return scan_result

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time

            scan_result = ScanResult(
                target_domain=target.domain,
                template_path=template.template_path,
                status=ScanStatus.TIMEOUT,
                findings=[],
                execution_time=execution_time,
                error_message="Scan timeout",
            )

            await self.ws_manager.send_log(
                self.session_id,
                "warning",
                f'Scan timeout: {target.domain} with {template.template_info.get("name", "unknown")}',
                phase="mass_scan",
            )

            return scan_result

        except Exception as e:
            execution_time = time.time() - start_time

            scan_result = ScanResult(
                target_domain=target.domain,
                template_path=template.template_path,
                status=ScanStatus.FAILED,
                findings=[],
                execution_time=execution_time,
                error_message=str(e),
            )

            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f'Scan failed: {target.domain} with {template.template_info.get("name", "unknown")} - {str(e)}',
                phase="mass_scan",
            )

            return scan_result

        finally:
            # Update target end time
            target.end_time = datetime.now().isoformat()

    async def _consolidate_results(self) -> None:
        """Consolidate scan results across all targets"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Consolidating scan results...", phase="mass_scan"
        )

        # Group findings by severity and template
        consolidated = {
            "total_findings": 0,
            "by_severity": {},
            "by_template": {},
            "by_domain": {},
            "failed_scans": [],
            "timeout_scans": [],
        }

        for result in self.scan_results:
            if result.status == ScanStatus.COMPLETED:
                consolidated["total_findings"] += len(result.findings)

                # Group by severity
                for finding in result.findings:
                    severity = finding.get("info", {}).get("severity", "unknown")
                    if severity not in consolidated["by_severity"]:
                        consolidated["by_severity"][severity] = []
                    consolidated["by_severity"][severity].append(finding)

                # Group by template
                template_name = Path(result.template_path).stem
                if template_name not in consolidated["by_template"]:
                    consolidated["by_template"][template_name] = []
                consolidated["by_template"][template_name].extend(result.findings)

                # Group by domain
                if result.target_domain not in consolidated["by_domain"]:
                    consolidated["by_domain"][result.target_domain] = []
                consolidated["by_domain"][result.target_domain].extend(result.findings)

            elif result.status == ScanStatus.FAILED:
                consolidated["failed_scans"].append(
                    {
                        "domain": result.target_domain,
                        "template": result.template_path,
                        "error": result.error_message,
                    }
                )

            elif result.status == ScanStatus.TIMEOUT:
                consolidated["timeout_scans"].append(
                    {
                        "domain": result.target_domain,
                        "template": result.template_path,
                        "execution_time": result.execution_time,
                    }
                )

        # Store consolidated results
        self.consolidated_results = consolidated

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f'Results consolidated: {consolidated["total_findings"]} total findings',
            phase="mass_scan",
        )

    async def _generate_reports(self) -> None:
        """Generate comprehensive reports"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating mass scan reports...",
            phase="mass_scan",
        )

        # Generate JSON report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_report_file = self.results_dir / f"mass_scan_report_{timestamp}.json"

        report_data = {
            "scan_info": {
                "session_id": self.session_id,
                "timestamp": timestamp,
                "targets_count": len(self.targets),
                "templates_count": len(self.templates),
                "valid_templates_count": len([t for t in self.templates if t.is_valid]),
                "scan_results_count": len(self.scan_results),
                "total_findings": self.consolidated_results.get("total_findings", 0),
            },
            "targets": [asdict(target) for target in self.targets],
            "templates": [asdict(template) for template in self.templates],
            "scan_results": [asdict(result) for result in self.scan_results],
            "consolidated_results": self.consolidated_results,
        }

        try:
            with open(json_report_file, "w") as f:
                json.dump(report_data, f, indent=2)

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Report saved: {json_report_file}",
                phase="mass_scan",
            )

        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def _compile_results(self) -> Dict[str, Any]:
        """Compile mass scan results"""
        return {
            "session_id": self.session_id,
            "module": "mass_scan",
            "scan_info": {
                "targets_count": len(self.targets),
                "templates_count": len(self.templates),
                "valid_templates_count": len([t for t in self.templates if t.is_valid]),
                "scan_results_count": len(self.scan_results),
                "total_findings": self.consolidated_results.get("total_findings", 0),
                "failed_scans": len(self.consolidated_results.get("failed_scans", [])),
                "timeout_scans": len(
                    self.consolidated_results.get("timeout_scans", [])
                ),
            },
            "targets": {
                "total_count": len(self.targets),
                "completed_count": len(
                    [t for t in self.targets if t.status == ScanStatus.COMPLETED]
                ),
                "failed_count": len(
                    [t for t in self.targets if t.status == ScanStatus.FAILED]
                ),
                "timeout_count": len(
                    [t for t in self.targets if t.status == ScanStatus.TIMEOUT]
                ),
                "results": [
                    asdict(target) for target in self.targets[:20]
                ],  # Limit for response size
            },
            "templates": {
                "total_count": len(self.templates),
                "valid_count": len([t for t in self.templates if t.is_valid]),
                "invalid_count": len([t for t in self.templates if not t.is_valid]),
                "results": [
                    asdict(template) for template in self.templates[:10]
                ],  # Limit for response size
            },
            "findings": {
                "total_count": self.consolidated_results.get("total_findings", 0),
                "by_severity": self.consolidated_results.get("by_severity", {}),
                "by_template": self.consolidated_results.get("by_template", {}),
                "by_domain": self.consolidated_results.get("by_domain", {}),
                "high_severity_count": len(
                    self.consolidated_results.get("by_severity", {}).get("critical", [])
                )
                + len(self.consolidated_results.get("by_severity", {}).get("high", [])),
            },
            "summary": {
                "targets_scanned": len(self.targets),
                "templates_used": len([t for t in self.templates if t.is_valid]),
                "total_findings": self.consolidated_results.get("total_findings", 0),
                "high_severity_findings": len(
                    self.consolidated_results.get("by_severity", {}).get("critical", [])
                )
                + len(self.consolidated_results.get("by_severity", {}).get("high", [])),
                "success_rate": len(
                    [t for t in self.targets if t.status == ScanStatus.COMPLETED]
                )
                / max(len(self.targets), 1),
                "recommendation": "Review high-severity findings and failed scans for further investigation",
            },
        }
