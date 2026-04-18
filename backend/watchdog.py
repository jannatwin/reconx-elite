"""
Watchdog Module - Continuous Monitoring and Baseline Management
Implements change detection and automated delta attack pipeline execution
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ai_router import AIRouter
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    SUBDOMAIN_ADDED = "subdomain_added"
    SUBDOMAIN_REMOVED = "subdomain_removed"
    JS_FILE_CHANGED = "js_file_changed"
    SSL_CERT_CHANGED = "ssl_cert_changed"
    HEADER_CHANGED = "header_changed"
    TECHNOLOGY_CHANGED = "technology_changed"
    ENDPOINT_CHANGED = "endpoint_changed"


@dataclass
class BaselineEntry:
    path: str
    hash_value: str
    timestamp: str
    metadata: Dict[str, Any]
    change_type: ChangeType


@dataclass
class ChangeDetection:
    change_type: ChangeType
    path: str
    old_value: Optional[str]
    new_value: Optional[str]
    confidence: float
    impact_assessment: str
    requires_full_scan: bool


@dataclass
class MonitoringConfig:
    target: str
    interval_minutes: int
    enable_subdomain_monitoring: bool
    enable_js_monitoring: bool
    enable_ssl_monitoring: bool
    enable_header_monitoring: bool
    enable_tech_monitoring: bool
    auto_execute_delta: bool
    baseline_retention_days: int


class Watchdog:
    """Continuous monitoring and change detection system"""

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
        config: Optional[MonitoringConfig] = None,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager
        self.config = config or self._default_config()

        # Storage for baseline and changes
        self.baseline: Dict[str, BaselineEntry] = {}
        self.detected_changes: List[ChangeDetection] = []
        self.monitoring_active = False

        # File paths
        self.baseline_dir = Path("baselines")
        self.baseline_file = (
            self.baseline_dir / f"{self.target.replace('.', '_')}_baseline.json"
        )
        self.changes_file = (
            self.baseline_dir / f"{self.target.replace('.', '_')}_changes.json"
        )

        # Ensure baseline directory exists
        self.baseline_dir.mkdir(exist_ok=True)

    def _default_config(self) -> MonitoringConfig:
        """Create default monitoring configuration"""
        return MonitoringConfig(
            target=self.target,
            interval_minutes=60,
            enable_subdomain_monitoring=True,
            enable_js_monitoring=True,
            enable_ssl_monitoring=True,
            enable_header_monitoring=True,
            enable_tech_monitoring=True,
            auto_execute_delta=False,
            baseline_retention_days=30,
        )

    async def execute(self, scan_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute watchdog monitoring"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting continuous monitoring...",
            phase="watchdog",
        )

        try:
            # Load existing baseline or create new one
            if scan_results:
                await self._create_baseline(scan_results)
            else:
                await self._load_baseline()

            # Start monitoring loop
            if self.config.auto_execute_delta:
                await self._start_monitoring_loop()
            else:
                await self._perform_single_check()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Watchdog monitoring completed: {len(self.detected_changes)} changes detected",
                phase="watchdog",
            )

            return results

        except Exception as e:
            logger.error(f"Watchdog execution failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Watchdog monitoring failed: {str(e)}",
                phase="watchdog",
            )
            raise

    async def _create_baseline(self, scan_results: Dict[str, Any]) -> None:
        """Create initial baseline from scan results"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Creating baseline from scan results...",
            phase="watchdog",
        )

        self.baseline.clear()
        timestamp = datetime.now().isoformat()

        # Extract subdomains
        if self.config.enable_subdomain_monitoring:
            await self._baseline_subdomains(scan_results, timestamp)

        # Extract JavaScript files
        if self.config.enable_js_monitoring:
            await self._baseline_js_files(scan_results, timestamp)

        # Extract SSL certificates
        if self.config.enable_ssl_monitoring:
            await self._baseline_ssl_certs(scan_results, timestamp)

        # Extract HTTP headers
        if self.config.enable_header_monitoring:
            await self._baseline_headers(scan_results, timestamp)

        # Extract technology stack
        if self.config.enable_tech_monitoring:
            await self._baseline_technology(scan_results, timestamp)

        # Save baseline to file
        await self._save_baseline()

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Baseline created with {len(self.baseline)} entries",
            phase="watchdog",
        )

    async def _baseline_subdomains(
        self, scan_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Baseline subdomain enumeration"""
        recon_results = scan_results.get("reconnaissance", {})
        subdomains = recon_results.get("subdomains", {}).get("results", [])

        for subdomain_data in subdomains:
            if isinstance(subdomain_data, dict):
                subdomain = subdomain_data.get("subdomain", "")
                if subdomain:
                    # Create hash of subdomain data
                    hash_value = self._calculate_hash(str(subdomain_data))

                    entry = BaselineEntry(
                        path=f"subdomain:{subdomain}",
                        hash_value=hash_value,
                        timestamp=timestamp,
                        metadata=subdomain_data,
                        change_type=ChangeType.SUBDOMAIN_ADDED,
                    )

                    self.baseline[entry.path] = entry

    async def _baseline_js_files(
        self, scan_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Baseline JavaScript files"""
        recon_results = scan_results.get("reconnaissance", {})
        js_assets = recon_results.get("js_assets", {}).get("results", [])

        for js_data in js_assets:
            if isinstance(js_data, dict):
                js_url = js_data.get("url", "")
                js_content = js_data.get("content", "")

                if js_url and js_content:
                    # Create hash of JS content
                    hash_value = self._calculate_hash(js_content)

                    entry = BaselineEntry(
                        path=f"js:{js_url}",
                        hash_value=hash_value,
                        timestamp=timestamp,
                        metadata=js_data,
                        change_type=ChangeType.JS_FILE_CHANGED,
                    )

                    self.baseline[entry.path] = entry

    async def _baseline_ssl_certs(
        self, scan_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Baseline SSL certificates"""
        recon_results = scan_results.get("reconnaissance", {})
        ssl_info = recon_results.get("ssl_info", {})

        if ssl_info:
            # Create hash of SSL certificate
            hash_value = self._calculate_hash(str(ssl_info))

            entry = BaselineEntry(
                path=f"ssl:{self.target}",
                hash_value=hash_value,
                timestamp=timestamp,
                metadata=ssl_info,
                change_type=ChangeType.SSL_CERT_CHANGED,
            )

            self.baseline[entry.path] = entry

    async def _baseline_headers(
        self, scan_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Baseline HTTP headers"""
        recon_results = scan_results.get("reconnaissance", {})
        headers_info = recon_results.get("headers", {})

        if headers_info:
            # Create hash of headers
            hash_value = self._calculate_hash(str(headers_info))

            entry = BaselineEntry(
                path=f"headers:{self.target}",
                hash_value=hash_value,
                timestamp=timestamp,
                metadata=headers_info,
                change_type=ChangeType.HEADER_CHANGED,
            )

            self.baseline[entry.path] = entry

    async def _baseline_technology(
        self, scan_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Baseline technology stack"""
        context_tree = scan_results.get("context_tree", {})
        tech_stack = context_tree.get("technology_stack", {})

        if tech_stack:
            # Create hash of technology stack
            hash_value = self._calculate_hash(str(tech_stack))

            entry = BaselineEntry(
                path=f"tech:{self.target}",
                hash_value=hash_value,
                timestamp=timestamp,
                metadata=tech_stack,
                change_type=ChangeType.TECHNOLOGY_CHANGED,
            )

            self.baseline[entry.path] = entry

    async def _load_baseline(self) -> None:
        """Load existing baseline from file"""
        if not self.baseline_file.exists():
            await self.ws_manager.send_log(
                self.session_id,
                "warning",
                "No existing baseline found",
                phase="watchdog",
            )
            return

        try:
            with open(self.baseline_file, "r") as f:
                baseline_data = json.load(f)

            self.baseline.clear()
            for path, entry_data in baseline_data.items():
                if isinstance(entry_data, dict):
                    entry = BaselineEntry(
                        path=entry_data["path"],
                        hash_value=entry_data["hash_value"],
                        timestamp=entry_data["timestamp"],
                        metadata=entry_data["metadata"],
                        change_type=ChangeType(entry_data["change_type"]),
                    )
                    self.baseline[path] = entry

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Loaded baseline with {len(self.baseline)} entries",
                phase="watchdog",
            )

        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Failed to load baseline: {str(e)}",
                phase="watchdog",
            )

    async def _save_baseline(self) -> None:
        """Save baseline to file"""
        try:
            baseline_data = {}
            for path, entry in self.baseline.items():
                baseline_data[path] = asdict(entry)

            with open(self.baseline_file, "w") as f:
                json.dump(baseline_data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")

    async def _start_monitoring_loop(self) -> None:
        """Start continuous monitoring loop"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Starting monitoring loop with {self.config.interval_minutes} minute interval",
            phase="watchdog",
        )

        self.monitoring_active = True

        while self.monitoring_active:
            try:
                await self._perform_single_check()

                # Wait for next interval
                await asyncio.sleep(self.config.interval_minutes * 60)

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retry

    async def _perform_single_check(self) -> None:
        """Perform single monitoring check"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Performing change detection check...",
            phase="watchdog",
        )

        # Clear previous changes
        self.detected_changes.clear()

        # Perform current scan
        current_results = await self._perform_current_scan()

        # Compare with baseline
        await self._detect_changes(current_results)

        # Save detected changes
        await self._save_changes()

        # Execute delta pipeline if changes detected and auto-execute enabled
        if self.detected_changes and self.config.auto_execute_delta:
            await self._execute_delta_pipeline(current_results)

    async def _perform_current_scan(self) -> Dict[str, Any]:
        """Perform current scan for comparison"""
        # This would typically call the reconnaissance pipeline
        # For now, we'll simulate with a basic check

        current_results = {
            "reconnaissance": {
                "subdomains": {"results": []},
                "js_assets": {"results": []},
                "ssl_info": {},
                "headers": {},
            },
            "context_tree": {"technology_stack": {}},
        }

        # In a real implementation, this would call the actual recon pipeline
        # For now, we'll just return empty results

        return current_results

    async def _detect_changes(self, current_results: Dict[str, Any]) -> None:
        """Detect changes between baseline and current results"""
        timestamp = datetime.now().isoformat()

        # Check subdomains
        if self.config.enable_subdomain_monitoring:
            await self._detect_subdomain_changes(current_results, timestamp)

        # Check JS files
        if self.config.enable_js_monitoring:
            await self._detect_js_changes(current_results, timestamp)

        # Check SSL certificates
        if self.config.enable_ssl_monitoring:
            await self._detect_ssl_changes(current_results, timestamp)

        # Check headers
        if self.config.enable_header_monitoring:
            await self._detect_header_changes(current_results, timestamp)

        # Check technology stack
        if self.config.enable_tech_monitoring:
            await self._detect_tech_changes(current_results, timestamp)

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Detected {len(self.detected_changes)} changes",
            phase="watchdog",
        )

    async def _detect_subdomain_changes(
        self, current_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Detect subdomain changes"""
        current_subdomains = set()
        current_subdomain_data = {}

        recon_results = current_results.get("reconnaissance", {})
        subdomains = recon_results.get("subdomains", {}).get("results", [])

        for subdomain_data in subdomains:
            if isinstance(subdomain_data, dict):
                subdomain = subdomain_data.get("subdomain", "")
                if subdomain:
                    current_subdomains.add(subdomain)
                    current_subdomain_data[subdomain] = subdomain_data

        # Get baseline subdomains
        baseline_subdomains = set()
        for path, entry in self.baseline.items():
            if path.startswith("subdomain:"):
                subdomain = path.split(":", 1)[1]
                baseline_subdomains.add(subdomain)

        # Detect added subdomains
        added_subdomains = current_subdomains - baseline_subdomains
        for subdomain in added_subdomains:
            subdomain_data = current_subdomain_data.get(subdomain, {})
            hash_value = self._calculate_hash(str(subdomain_data))

            change = ChangeDetection(
                change_type=ChangeType.SUBDOMAIN_ADDED,
                path=f"subdomain:{subdomain}",
                old_value=None,
                new_value=subdomain,
                confidence=0.9,
                impact_assessment="New subdomain discovered - potential attack surface",
                requires_full_scan=True,
            )

            self.detected_changes.append(change)

        # Detect removed subdomains
        removed_subdomains = baseline_subdomains - current_subdomains
        for subdomain in removed_subdomains:
            change = ChangeDetection(
                change_type=ChangeType.SUBDOMAIN_REMOVED,
                path=f"subdomain:{subdomain}",
                old_value=subdomain,
                new_value=None,
                confidence=0.8,
                impact_assessment="Subdomain no longer accessible - potential infrastructure change",
                requires_full_scan=False,
            )

            self.detected_changes.append(change)

    async def _detect_js_changes(
        self, current_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Detect JavaScript file changes"""
        current_js_files = {}

        recon_results = current_results.get("reconnaissance", {})
        js_assets = recon_results.get("js_assets", {}).get("results", [])

        for js_data in js_assets:
            if isinstance(js_data, dict):
                js_url = js_data.get("url", "")
                js_content = js_data.get("content", "")

                if js_url and js_content:
                    current_js_files[js_url] = js_data

        # Compare with baseline
        for path, entry in self.baseline.items():
            if path.startswith("js:"):
                js_url = path.split(":", 1)[1]

                if js_url in current_js_files:
                    current_js_data = current_js_files[js_url]
                    current_hash = self._calculate_hash(
                        current_js_data.get("content", "")
                    )

                    if current_hash != entry.hash_value:
                        change = ChangeDetection(
                            change_type=ChangeType.JS_FILE_CHANGED,
                            path=path,
                            old_value=entry.hash_value,
                            new_value=current_hash,
                            confidence=0.9,
                            impact_assessment="JavaScript file content changed - potential functionality update",
                            requires_full_scan=True,
                        )

                        self.detected_changes.append(change)

    async def _detect_ssl_changes(
        self, current_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Detect SSL certificate changes"""
        recon_results = current_results.get("reconnaissance", {})
        current_ssl = recon_results.get("ssl_info", {})

        baseline_path = f"ssl:{self.target}"
        if baseline_path in self.baseline:
            baseline_entry = self.baseline[baseline_path]
            current_hash = self._calculate_hash(str(current_ssl))

            if current_hash != baseline_entry.hash_value:
                change = ChangeDetection(
                    change_type=ChangeType.SSL_CERT_CHANGED,
                    path=baseline_path,
                    old_value=baseline_entry.hash_value,
                    new_value=current_hash,
                    confidence=0.8,
                    impact_assessment="SSL certificate changed - potential security configuration update",
                    requires_full_scan=False,
                )

                self.detected_changes.append(change)

    async def _detect_header_changes(
        self, current_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Detect HTTP header changes"""
        recon_results = current_results.get("reconnaissance", {})
        current_headers = recon_results.get("headers", {})

        baseline_path = f"headers:{self.target}"
        if baseline_path in self.baseline:
            baseline_entry = self.baseline[baseline_path]
            current_hash = self._calculate_hash(str(current_headers))

            if current_hash != baseline_entry.hash_value:
                change = ChangeDetection(
                    change_type=ChangeType.HEADER_CHANGED,
                    path=baseline_path,
                    old_value=baseline_entry.hash_value,
                    new_value=current_hash,
                    confidence=0.7,
                    impact_assessment="HTTP headers changed - potential server configuration update",
                    requires_full_scan=False,
                )

                self.detected_changes.append(change)

    async def _detect_tech_changes(
        self, current_results: Dict[str, Any], timestamp: str
    ) -> None:
        """Detect technology stack changes"""
        context_tree = current_results.get("context_tree", {})
        current_tech = context_tree.get("technology_stack", {})

        baseline_path = f"tech:{self.target}"
        if baseline_path in self.baseline:
            baseline_entry = self.baseline[baseline_path]
            current_hash = self._calculate_hash(str(current_tech))

            if current_hash != baseline_entry.hash_value:
                change = ChangeDetection(
                    change_type=ChangeType.TECHNOLOGY_CHANGED,
                    path=baseline_path,
                    old_value=baseline_entry.hash_value,
                    new_value=current_hash,
                    confidence=0.8,
                    impact_assessment="Technology stack changed - potential framework or library update",
                    requires_full_scan=True,
                )

                self.detected_changes.append(change)

    async def _save_changes(self) -> None:
        """Save detected changes to file"""
        try:
            changes_data = {
                "timestamp": datetime.now().isoformat(),
                "target": self.target,
                "changes": [asdict(change) for change in self.detected_changes],
            }

            with open(self.changes_file, "w") as f:
                json.dump(changes_data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save changes: {e}")

    async def _execute_delta_pipeline(self, current_results: Dict[str, Any]) -> None:
        """Execute delta attack pipeline on changed assets"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Executing delta attack pipeline...",
            phase="watchdog",
        )

        # Filter changes that require full scan
        high_impact_changes = [c for c in self.detected_changes if c.requires_full_scan]

        if not high_impact_changes:
            await self.ws_manager.send_log(
                self.session_id,
                "info",
                "No high-impact changes detected, skipping delta execution",
                phase="watchdog",
            )
            return

        # In a real implementation, this would trigger the appropriate phases
        # For now, we'll just log the changes
        for change in high_impact_changes:
            await self.ws_manager.send_log(
                self.session_id,
                "warning",
                f"High-impact change detected: {change.change_type.value} at {change.path}",
                phase="watchdog",
            )

    def _calculate_hash(self, data: str) -> str:
        """Calculate SHA-256 hash of data"""
        return hashlib.sha256(data.encode()).hexdigest()

    def _compile_results(self) -> Dict[str, Any]:
        """Compile watchdog monitoring results"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "module": "watchdog",
            "baseline": {
                "total_entries": len(self.baseline),
                "subdomain_count": len(
                    [p for p in self.baseline.keys() if p.startswith("subdomain:")]
                ),
                "js_file_count": len(
                    [p for p in self.baseline.keys() if p.startswith("js:")]
                ),
                "ssl_count": len(
                    [p for p in self.baseline.keys() if p.startswith("ssl:")]
                ),
                "header_count": len(
                    [p for p in self.baseline.keys() if p.startswith("headers:")]
                ),
                "tech_count": len(
                    [p for p in self.baseline.keys() if p.startswith("tech:")]
                ),
                "baseline_timestamp": self.baseline.get("subdomain:example", {}).get(
                    "timestamp", "unknown"
                ),
            },
            "changes": {
                "total_changes": len(self.detected_changes),
                "change_types": list(
                    set(c.change_type.value for c in self.detected_changes)
                ),
                "high_impact_changes": len(
                    [c for c in self.detected_changes if c.requires_full_scan]
                ),
                "results": [asdict(change) for change in self.detected_changes],
            },
            "configuration": {
                "interval_minutes": self.config.interval_minutes,
                "auto_execute_delta": self.config.auto_execute_delta,
                "monitoring_active": self.monitoring_active,
                "subdomain_monitoring": self.config.enable_subdomain_monitoring,
                "js_monitoring": self.config.enable_js_monitoring,
                "ssl_monitoring": self.config.enable_ssl_monitoring,
                "header_monitoring": self.config.enable_header_monitoring,
                "tech_monitoring": self.config.enable_tech_monitoring,
            },
            "summary": {
                "baseline_entries": len(self.baseline),
                "changes_detected": len(self.detected_changes),
                "high_impact_changes": len(
                    [c for c in self.detected_changes if c.requires_full_scan]
                ),
                "monitoring_active": self.monitoring_active,
                "recommendation": "Review detected changes and consider full scan for high-impact modifications",
            },
        }

    def stop_monitoring(self) -> None:
        """Stop monitoring loop"""
        self.monitoring_active = False
        logger.info("Monitoring loop stopped")
