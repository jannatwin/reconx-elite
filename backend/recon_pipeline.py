"""
Enhanced ReconPipeline - Phase 1 of Agentic Multi-Model Vulnerability Research Engine
Implements recursive subdomain discovery, cloud asset mapping, and port intelligence
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

from ai_router import AIRouter
from phase_1_cloud_hunter import CloudHunter
from phase_1_acquisition_mapper import AcquisitionMapper
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    subdomain: str
    source: str
    confidence: float
    level: int  # Discovery depth level
    ai_predicted: bool = False


@dataclass
class CloudAsset:
    asset_type: str  # s3, azure, gcp
    name: str
    region: str
    permissions: List[str]
    accessible: bool


@dataclass
class PortResult:
    host: str
    port: int
    service: str
    status: str
    confidence: float


@dataclass
class AcquisitionTarget:
    domain: str
    ip_ranges: List[str]
    whois_data: Dict[str, Any]
    relationship_type: str  # subsidiary, partner, etc.


class ReconPipeline:
    """Enhanced reconnaissance pipeline with AI-driven discovery"""

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
        max_depth: int = 3,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager
        self.max_depth = max_depth

        # Initialize specialized components
        self.cloud_hunter = CloudHunter(session_id, ws_manager)
        self.acquisition_mapper = AcquisitionMapper(session_id, ws_manager)

        # Storage for results
        self.discovered_subdomains: Set[str] = set()
        self.subdomain_results: List[SubdomainResult] = []
        self.cloud_assets: List[CloudAsset] = []
        self.port_results: List[PortResult] = []
        self.acquisition_targets: List[AcquisitionTarget] = []

        # Common dev ports to scan
        self.dev_ports = [3000, 5000, 8000, 8080, 8443, 9000, 9090]

    async def execute(self) -> Dict[str, Any]:
        """Execute the complete reconnaissance pipeline"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Starting enhanced reconnaissance for {self.target}",
            phase="recon_pipeline",
        )

        try:
            # Phase 1.1: Initial Subdomain Discovery
            await self._initial_subdomain_discovery()

            # Phase 1.2: AI-Powered Recursive Discovery
            await self._recursive_ai_discovery()

            # Phase 1.3: Cloud Asset Discovery
            await self._enhanced_cloud_discovery()

            # Phase 1.4: Port Intelligence Scanning
            await self._port_intelligence_scan()

            # Phase 1.5: Acquisition Mapping
            await self._acquisition_mapping()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Reconnaissance completed: {len(self.subdomain_results)} subdomains, "
                f"{len(self.cloud_assets)} cloud assets, {len(self.port_results)} ports",
                phase="recon_pipeline",
            )

            return results

        except Exception as e:
            logger.error(f"ReconPipeline execution failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Reconnaissance failed: {str(e)}",
                phase="recon_pipeline",
            )
            raise

    async def _initial_subdomain_discovery(self) -> None:
        """Initial subdomain discovery using traditional tools"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting initial subdomain discovery...",
            phase="subdomain_discovery",
        )

        # Use existing tool integrations as data providers
        tools = ["subfinder", "sublist3r", "findomain", "crt.sh"]

        for tool in tools:
            try:
                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"Running {tool}...",
                    phase="subdomain_discovery",
                )

                # Execute tool through tool_runner
                result = await self.tool_runner.run_tool(tool, self.target)

                if result and result.get("output"):
                    subdomains = self._parse_subdomain_output(result["output"])
                    for subdomain in subdomains:
                        if subdomain not in self.discovered_subdomains:
                            self.discovered_subdomains.add(subdomain)
                            self.subdomain_results.append(
                                SubdomainResult(
                                    subdomain=subdomain,
                                    source=tool,
                                    confidence=0.8,
                                    level=1,
                                    ai_predicted=False,
                                )
                            )

                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"{tool} completed. Found {len(subdomains) if result else 0} subdomains",
                    phase="subdomain_discovery",
                )

            except Exception as e:
                logger.error(f"Tool {tool} failed: {e}")
                await self.ws_manager.send_log(
                    self.session_id,
                    "warning",
                    f"Tool {tool} failed: {str(e)}",
                    phase="subdomain_discovery",
                )

    async def _recursive_ai_discovery(self) -> None:
        """AI-powered recursive subdomain discovery (3 levels deep)"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting AI-powered recursive discovery...",
            phase="ai_discovery",
        )

        current_level_subdomains = {
            r.subdomain for r in self.subdomain_results if r.level == 1
        }

        for level in range(2, self.max_depth + 1):
            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Discovering level {level} subdomains...",
                phase="ai_discovery",
            )

            # Use AI to predict hidden subdomains
            ai_predictions = await self._predict_hidden_subdomains(
                current_level_subdomains, level
            )

            # Validate AI predictions
            validated_subdomains = await self._validate_ai_predictions(ai_predictions)

            # Add validated results
            for subdomain in validated_subdomains:
                if subdomain not in self.discovered_subdomains:
                    self.discovered_subdomains.add(subdomain)
                    self.subdomain_results.append(
                        SubdomainResult(
                            subdomain=subdomain,
                            source="ai_prediction",
                            confidence=0.6,  # Lower confidence for AI predictions
                            level=level,
                            ai_predicted=True,
                        )
                    )

            # Prepare for next level
            current_level_subdomains = set(validated_subdomains)

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Level {level} completed. Found {len(validated_subdomains)} new subdomains",
                phase="ai_discovery",
            )

    async def _predict_hidden_subdomains(
        self, known_subdomains: Set[str], level: int
    ) -> List[str]:
        """Use AI to predict potential hidden subdomains"""
        if not known_subdomains:
            return []

        # Extract patterns from known subdomains
        patterns = self._extract_subdomain_patterns(known_subdomains)

        # Create AI prompt for prediction
        prompt = f"""
        Based on the following known subdomains for {self.target}, predict potential hidden subdomains at level {level}.

        Known subdomains: {list(known_subdomains)[:20]}  # Limit to prevent token overflow
        Observed patterns: {patterns[:10]}

        Generate 15-20 potential hidden subdomains that might exist but weren't discovered by traditional tools.
        Consider:
        - Development/staging environments (dev, staging, qa, test)
        - Internal services (admin, api, internal, private)
        - Geographic/region-specific (us, eu, asia, local)
        - Service-specific (auth, payment, analytics, metrics)
        - Version-specific (v1, v2, v3, legacy)
        
        Return only the subdomain names, one per line, without the domain suffix.
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",  # Use fast model for pattern recognition
                prompt=prompt,
                max_tokens=500,
            )

            if result.get("output"):
                predictions = result["output"].strip().split("\n")
                # Clean and format predictions
                cleaned_predictions = []
                for pred in predictions:
                    pred = pred.strip()
                    if pred and not pred.startswith("#"):
                        # Add domain suffix if missing
                        if "." not in pred:
                            cleaned_predictions.append(f"{pred}.{self.target}")
                        else:
                            cleaned_predictions.append(pred)

                return cleaned_predictions[:20]  # Limit predictions

        except Exception as e:
            logger.error(f"AI prediction failed: {e}")

        return []

    def _extract_subdomain_patterns(self, subdomains: Set[str]) -> List[str]:
        """Extract common patterns from known subdomains"""
        patterns = []
        for subdomain in subdomains:
            parts = subdomain.split(".")
            if len(parts) >= 2:
                patterns.append(parts[0])  # Extract first part as pattern

        # Count pattern frequency
        pattern_counts = {}
        for pattern in patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        # Return most common patterns
        sorted_patterns = sorted(
            pattern_counts.items(), key=lambda x: x[1], reverse=True
        )
        return [pattern for pattern, count in sorted_patterns if count > 1]

    async def _validate_ai_predictions(self, predictions: List[str]) -> List[str]:
        """Validate AI-predicted subdomains using DNS resolution"""
        validated = []

        for prediction in predictions:
            try:
                # Use DNS resolution to validate
                result = await self.tool_runner.run_tool("dns_resolve", prediction)

                if result and result.get("success"):
                    validated.append(prediction)

            except Exception as e:
                logger.debug(f"Validation failed for {prediction}: {e}")

        return validated

    async def _enhanced_cloud_discovery(self) -> None:
        """Enhanced cloud asset discovery with AI permutation"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting enhanced cloud asset discovery...",
            phase="cloud_discovery",
        )

        # Use existing cloud hunter
        cloud_results = await self.cloud_hunter.hunt_cloud_assets(self.target)

        # AI-powered brand name permutation for additional cloud assets
        ai_permutations = await self._ai_cloud_permutation()

        # Validate AI permutations
        for permuted_asset in ai_permutations:
            try:
                validation_result = await self._validate_cloud_asset(permuted_asset)
                if validation_result:
                    self.cloud_assets.append(validation_result)
            except Exception as e:
                logger.debug(f"Cloud asset validation failed: {e}")

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Cloud discovery completed: {len(self.cloud_assets)} assets found",
            phase="cloud_discovery",
        )

    async def _ai_cloud_permutation(self) -> List[Dict[str, Any]]:
        """Use AI to generate cloud asset name permutations"""
        brand_name = self.target.split(".")[0].upper()

        prompt = f"""
        Generate potential cloud asset names for brand "{brand_name}".
        Consider variations for:
        - AWS S3 buckets (brand-name-backups, brand-name-data, etc.)
        - Azure blob storage (brandnamestorage, brand-archive, etc.)
        - Google Cloud Storage (brand_name_assets, brand-data-lake, etc.)
        
        Generate 10-15 permutations for each cloud provider.
        Return as JSON format: {{"aws": ["bucket1", "bucket2"], "azure": ["container1"], "gcp": ["bucket1"]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst", prompt=prompt, max_tokens=300
            )

            if result.get("output"):
                # Parse JSON response
                try:
                    permutations = json.loads(result["output"])
                    return permutations
                except json.JSONDecodeError:
                    logger.warning("AI cloud permutation response not valid JSON")

        except Exception as e:
            logger.error(f"AI cloud permutation failed: {e}")

        return {}

    async def _validate_cloud_asset(
        self, asset_info: Dict[str, Any]
    ) -> Optional[CloudAsset]:
        """Validate cloud asset accessibility"""
        asset_type = asset_info.get("type", "s3")
        asset_name = asset_info.get("name", "")

        try:
            # Use appropriate validation based on asset type
            if asset_type == "s3":
                result = await self.tool_runner.run_tool("s3_check", asset_name)
            elif asset_type == "azure":
                result = await self.tool_runner.run_tool("azure_check", asset_name)
            elif asset_type == "gcp":
                result = await self.tool_runner.run_tool("gcp_check", asset_name)
            else:
                return None

            if result and result.get("accessible"):
                return CloudAsset(
                    asset_type=asset_type,
                    name=asset_name,
                    region=result.get("region", "unknown"),
                    permissions=result.get("permissions", []),
                    accessible=True,
                )

        except Exception as e:
            logger.debug(f"Cloud asset validation failed: {e}")

        return None

    async def _port_intelligence_scan(self) -> None:
        """Intelligent port scanning including dev ports"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting port intelligence scanning...",
            phase="port_scanning",
        )

        # Get live hosts from discovered subdomains
        live_hosts = await self._get_live_hosts()

        # Combine standard ports with dev ports
        all_ports = list(range(1, 1001)) + self.dev_ports

        for host in live_hosts[:50]:  # Limit to prevent excessive scanning
            try:
                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"Scanning ports on {host}...",
                    phase="port_scanning",
                )

                # Use nmap for port scanning
                scan_result = await self.tool_runner.run_tool(
                    "nmap_scan",
                    f'--top-ports 1000 -p {",".join(map(str, self.dev_ports))} {host}',
                )

                if scan_result and scan_result.get("output"):
                    ports = self._parse_nmap_output(scan_result["output"], host)
                    self.port_results.extend(ports)

            except Exception as e:
                logger.error(f"Port scan failed for {host}: {e}")

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Port scanning completed: {len(self.port_results)} ports found",
            phase="port_scanning",
        )

    async def _get_live_hosts(self) -> List[str]:
        """Get list of live hosts from discovered subdomains"""
        live_hosts = []

        for subdomain in self.discovered_subdomains:
            try:
                # Use httpx or similar to check if host is alive
                result = await self.tool_runner.run_tool("http_probe", subdomain)

                if result and result.get("alive"):
                    live_hosts.append(subdomain)

            except Exception as e:
                logger.debug(f"Host probe failed for {subdomain}: {e}")

        return live_hosts

    def _parse_nmap_output(self, output: str, host: str) -> List[PortResult]:
        """Parse nmap output to extract port information"""
        ports = []

        # Parse nmap output for open ports
        for line in output.split("\n"):
            if "/tcp" in line and "open" in line:
                try:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_service = parts[0]
                        port = int(port_service.split("/")[0])
                        service = parts[2] if len(parts) > 2 else "unknown"
                        status = "open"

                        ports.append(
                            PortResult(
                                host=host,
                                port=port,
                                service=service,
                                status=status,
                                confidence=0.9,
                            )
                        )
                except (ValueError, IndexError):
                    continue

        return ports

    async def _acquisition_mapping(self) -> None:
        """Map subsidiary domains and acquisition targets"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting acquisition mapping...",
            phase="acquisition_mapping",
        )

        # Use existing acquisition mapper
        acquisition_results = await self.acquisition_mapper.map_acquisitions(
            self.target
        )

        # Convert to AcquisitionTarget objects
        for result in acquisition_results:
            self.acquisition_targets.append(
                AcquisitionTarget(
                    domain=result.get("domain", ""),
                    ip_ranges=result.get("ip_ranges", []),
                    whois_data=result.get("whois_data", {}),
                    relationship_type=result.get("relationship_type", "unknown"),
                )
            )

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Acquisition mapping completed: {len(self.acquisition_targets)} targets found",
            phase="acquisition_mapping",
        )

    def _parse_subdomain_output(self, output: str) -> List[str]:
        """Parse subdomain discovery tool output"""
        subdomains = []

        for line in output.split("\n"):
            line = line.strip()
            if line and self.target in line:
                # Extract subdomain from line
                if self.target in line:
                    # Simple extraction - can be enhanced based on tool format
                    parts = line.split()
                    for part in parts:
                        if self.target in part and "." in part:
                            subdomains.append(part.strip())

        return list(set(subdomains))  # Remove duplicates

    def _compile_results(self) -> Dict[str, Any]:
        """Compile all reconnaissance results"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "subdomains": {
                "total_count": len(self.subdomain_results),
                "results": [asdict(result) for result in self.subdomain_results],
                "ai_predicted_count": len(
                    [r for r in self.subdomain_results if r.ai_predicted]
                ),
            },
            "cloud_assets": {
                "total_count": len(self.cloud_assets),
                "results": [asdict(asset) for asset in self.cloud_assets],
                "accessible_count": len([a for a in self.cloud_assets if a.accessible]),
            },
            "ports": {
                "total_count": len(self.port_results),
                "results": [asdict(port) for port in self.port_results],
                "dev_ports_found": len(
                    [p for p in self.port_results if p.port in self.dev_ports]
                ),
            },
            "acquisitions": {
                "total_count": len(self.acquisition_targets),
                "results": [asdict(target) for target in self.acquisition_targets],
            },
            "summary": {
                "total_discoveries": len(self.subdomain_results)
                + len(self.cloud_assets)
                + len(self.port_results),
                "discovery_depth": self.max_depth,
                "ai_enhanced": True,
            },
        }
