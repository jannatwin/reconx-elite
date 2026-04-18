"""Session manifest handler for tracking state and deduplication across phases."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class SessionManifest:
    """Manages session state, phase completion, and prevents duplicate work."""

    def __init__(self, session_id: str, manifest_dir: str = "./session_manifests"):
        self.session_id = session_id
        self.manifest_dir = Path(manifest_dir)
        self.manifest_dir.mkdir(exist_ok=True)
        self.manifest_path = self.manifest_dir / f"{session_id}.json"
        self.data = self._load_or_create()

    def _load_or_create(self) -> dict[str, Any]:
        """Load existing manifest or create new."""
        if self.manifest_path.exists():
            with open(self.manifest_path, "r") as f:
                return json.load(f)

        return {
            "session_id": self.session_id,
            "created_at": datetime.utcnow().isoformat(),
            "phases": {
                "phase_1": {"status": "pending", "findings": [], "completed_at": None},
                "phase_2": {"status": "pending", "findings": [], "completed_at": None},
                "phase_3": {"status": "pending", "findings": [], "completed_at": None},
                "phase_4": {"status": "pending", "findings": [], "completed_at": None},
                "phase_5": {"status": "pending", "findings": [], "completed_at": None},
                "phase_6": {"status": "pending", "findings": [], "completed_at": None},
                "phase_7": {"status": "pending", "summary": {}, "completed_at": None},
            },
            "context_tree": {
                "target": None,
                "subdomains": [],
                "live_hosts": [],
                "open_ports": [],
                "cloud_buckets": [],
                "subsidiaries": [],
                "tech_stack": {},
                "cve_findings": [],
                "api_endpoints": [],
                "idor_targets": [],
                "vulnerability_findings": [],
                "pocs": [],
            },
            "deduplication": {
                "checked_subdomains": set(),
                "checked_ports": set(),
                "checked_urls": set(),
                "tested_idor_pairs": set(),
                "tested_ssrf_params": set(),
            },
        }

    def save(self) -> None:
        """Persist manifest to disk, converting sets to lists."""
        data_to_save = self.data.copy()
        data_to_save["deduplication"] = {
            k: list(v) if isinstance(v, set) else v
            for k, v in self.data["deduplication"].items()
        }
        with open(self.manifest_path, "w") as f:
            json.dump(data_to_save, f, indent=2, default=str)

    def update_phase(
        self, phase: str, status: str, findings: list[dict] | None = None
    ) -> None:
        """Update phase status and findings."""
        if phase in self.data["phases"]:
            self.data["phases"][phase]["status"] = status
            if findings:
                self.data["phases"][phase]["findings"].extend(findings)
            if status == "completed":
                self.data["phases"][phase][
                    "completed_at"
                ] = datetime.utcnow().isoformat()
        self.save()

    def add_context(self, context_type: str, data: Any) -> None:
        """Add data to context tree."""
        if context_type == "subdomains" and isinstance(data, list):
            self.data["context_tree"]["subdomains"].extend(data)
            self.data["context_tree"]["subdomains"] = list(
                set(self.data["context_tree"]["subdomains"])
            )
        elif context_type == "live_hosts" and isinstance(data, list):
            self.data["context_tree"]["live_hosts"].extend(data)
        elif context_type == "open_ports" and isinstance(data, dict):
            for host, ports in data.items():
                self.data["context_tree"]["open_ports"].append(
                    {"host": host, "ports": ports}
                )
        elif context_type == "tech_stack" and isinstance(data, dict):
            self.data["context_tree"]["tech_stack"].update(data)
        elif context_type == "cve_findings" and isinstance(data, list):
            self.data["context_tree"]["cve_findings"].extend(data)
        elif context_type == "api_endpoints" and isinstance(data, list):
            self.data["context_tree"]["api_endpoints"].extend(data)
        elif context_type == "idor_targets" and isinstance(data, list):
            self.data["context_tree"]["idor_targets"].extend(data)
        elif context_type == "vulnerability_findings" and isinstance(data, list):
            self.data["context_tree"]["vulnerability_findings"].extend(data)
        elif context_type == "pocs" and isinstance(data, list):
            self.data["context_tree"]["pocs"].extend(data)
        self.save()

    def already_checked(self, check_type: str, value: str) -> bool:
        """Check if value was already processed."""
        if check_type in self.data["deduplication"]:
            return value in self.data["deduplication"][check_type]
        return False

    def mark_checked(self, check_type: str, value: str) -> None:
        """Mark value as processed."""
        if check_type in self.data["deduplication"]:
            if isinstance(self.data["deduplication"][check_type], set):
                self.data["deduplication"][check_type].add(value)
            else:
                self.data["deduplication"][check_type] = set(
                    self.data["deduplication"][check_type]
                )
                self.data["deduplication"][check_type].add(value)
        self.save()

    def get_phase_status(self, phase: str) -> str:
        """Get phase status."""
        return self.data["phases"].get(phase, {}).get("status", "unknown")

    def all_phases_before_completed(self, phase_num: int) -> bool:
        """Check if all phases before this one are completed."""
        for i in range(1, phase_num):
            phase_key = f"phase_{i}"
            if self.data["phases"][phase_key]["status"] != "completed":
                return False
        return True
