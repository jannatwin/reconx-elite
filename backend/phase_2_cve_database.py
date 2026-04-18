"""Phase 2: CVE Database - Local cache for version-to-CVE lookups."""

import json
from pathlib import Path
from typing import Any


class CVEDatabase:
    """Local CVE database for quick version lookups and low-hanging fruit detection."""

    def __init__(self, db_path: str = "./cve_cache.json"):
        self.db_path = Path(db_path)
        self.data = self._load_or_create()

    def _load_or_create(self) -> dict[str, Any]:
        """Load CVE cache or create default."""
        if self.db_path.exists():
            with open(self.db_path, "r") as f:
                return json.load(f)

        # Default CVE mappings for common software
        return {
            "Django": {
                "2.0": [
                    {
                        "cve": "CVE-2019-14234",
                        "severity": "HIGH",
                        "title": "SQL Injection",
                    },
                    {
                        "cve": "CVE-2019-12308",
                        "severity": "MEDIUM",
                        "title": "Information Disclosure",
                    },
                ],
                "2.2": [
                    {
                        "cve": "CVE-2020-9402",
                        "severity": "MEDIUM",
                        "title": "SQL Injection",
                    },
                ],
                "3.0": [
                    {
                        "cve": "CVE-2021-33571",
                        "severity": "LOW",
                        "title": "Denial of Service",
                    },
                ],
            },
            "Spring Boot": {
                "1.5": [
                    {
                        "cve": "CVE-2018-1272",
                        "severity": "CRITICAL",
                        "title": "Remote Code Execution",
                    },
                ],
                "2.0": [
                    {
                        "cve": "CVE-2019-2725",
                        "severity": "HIGH",
                        "title": "Arbitrary Code Execution",
                    },
                ],
                "2.2": [
                    {
                        "cve": "CVE-2020-1938",
                        "severity": "CRITICAL",
                        "title": "RCE via Tomcat",
                    },
                ],
            },
            "Laravel": {
                "5.0": [
                    {
                        "cve": "CVE-2017-8672",
                        "severity": "MEDIUM",
                        "title": "Authentication Bypass",
                    },
                ],
                "6.0": [
                    {
                        "cve": "CVE-2019-9081",
                        "severity": "LOW",
                        "title": "CSRF Token Exposure",
                    },
                ],
            },
            "WordPress": {
                "4.0": [
                    {
                        "cve": "CVE-2015-2213",
                        "severity": "HIGH",
                        "title": "SQL Injection",
                    },
                ],
                "5.0": [
                    {
                        "cve": "CVE-2019-8943",
                        "severity": "CRITICAL",
                        "title": "RCE via File Upload",
                    },
                ],
            },
            "Node.js Express": {
                "4.0": [
                    {
                        "cve": "CVE-2015-8859",
                        "severity": "MEDIUM",
                        "title": "Open Redirect",
                    },
                ],
                "4.16": [
                    {
                        "cve": "CVE-2017-14849",
                        "severity": "LOW",
                        "title": "Information Disclosure",
                    },
                ],
            },
            # 2026 Critical CVEs
            "Langflow": {
                "1.8.2": [
                    {
                        "cve": "CVE-2026-33017",
                        "severity": "CRITICAL",
                        "title": "Remote Code Execution",
                    },
                    {
                        "cve": "CVE-2025-3248",
                        "severity": "HIGH",
                        "title": "Code Injection",
                    },
                ],
                "1.8.1": [
                    {
                        "cve": "CVE-2026-33017",
                        "severity": "CRITICAL",
                        "title": "Remote Code Execution",
                    },
                    {
                        "cve": "CVE-2025-3248",
                        "severity": "HIGH",
                        "title": "Code Injection",
                    },
                ],
                "1.8.0": [
                    {
                        "cve": "CVE-2026-33017",
                        "severity": "CRITICAL",
                        "title": "Remote Code Execution",
                    },
                ],
            },
            "Trivy": {
                "0.69.4": [
                    {
                        "cve": "CVE-2026-33634",
                        "severity": "CRITICAL",
                        "title": "Supply Chain Compromise",
                    },
                ],
                "0.69.3": [
                    {
                        "cve": "CVE-2026-33634",
                        "severity": "HIGH",
                        "title": "Supply Chain Risk",
                    },
                ],
            },
            "Microsoft SQL Server": {
                "2022": [
                    {
                        "cve": "CVE-2026-21262",
                        "severity": "HIGH",
                        "title": "Elevation of Privilege",
                    },
                    {
                        "cve": "CVE-2026-26115",
                        "severity": "HIGH",
                        "title": "Elevation of Privilege",
                    },
                    {
                        "cve": "CVE-2026-26116",
                        "severity": "HIGH",
                        "title": "Elevation of Privilege",
                    },
                ],
                "2019": [
                    {
                        "cve": "CVE-2026-21262",
                        "severity": "HIGH",
                        "title": "Elevation of Privilege",
                    },
                ],
            },
            ".NET": {
                "10.0": [
                    {
                        "cve": "CVE-2026-26127",
                        "severity": "HIGH",
                        "title": "Denial of Service",
                    },
                    {
                        "cve": "CVE-2026-26131",
                        "severity": "HIGH",
                        "title": "Elevation of Privilege",
                    },
                ],
                "9.0": [
                    {
                        "cve": "CVE-2026-26127",
                        "severity": "HIGH",
                        "title": "Denial of Service",
                    },
                ],
                "8.0": [
                    {
                        "cve": "CVE-2026-26127",
                        "severity": "MEDIUM",
                        "title": "Denial of Service",
                    },
                ],
            },
            "Cisco FMC": {
                "7.0": [
                    {
                        "cve": "CVE-2026-20131",
                        "severity": "CRITICAL",
                        "title": "Zero-Day RCE",
                    },
                ],
                "6.7": [
                    {
                        "cve": "CVE-2026-20131",
                        "severity": "CRITICAL",
                        "title": "Zero-Day RCE",
                    },
                ],
            },
            "LiteLLM": {
                "1.0.0": [
                    {
                        "cve": "CVE-2026-33634",
                        "severity": "CRITICAL",
                        "title": "Supply Chain Compromise",
                    },
                ],
            },
        }

    def lookup_cves(self, software_name: str, version: str) -> list[dict[str, Any]]:
        """Find CVEs for a specific software version."""
        if software_name in self.data:
            # Try exact match first
            if version in self.data[software_name]:
                return self.data[software_name][version]

            # Try major version match
            major_version = version.split(".")[0]
            for stored_version in self.data[software_name].keys():
                if stored_version.startswith(major_version):
                    return self.data[software_name][stored_version]

        return []

    def get_low_hanging_fruit(self, tech_stack: dict[str, str]) -> list[dict[str, Any]]:
        """Find critical/high severity CVEs in the detected tech stack."""
        findings = []
        for software, version in tech_stack.items():
            cves = self.lookup_cves(software, version)
            for cve in cves:
                if cve["severity"] in ["CRITICAL", "HIGH"]:
                    findings.append(
                        {
                            "software": software,
                            "version": version,
                            "cve": cve["cve"],
                            "severity": cve["severity"],
                            "title": cve["title"],
                            "exploitability": "high",
                        }
                    )
        return findings

    def add_cve(self, software: str, version: str, cve_info: dict[str, Any]) -> None:
        """Add a CVE to the database."""
        if software not in self.data:
            self.data[software] = {}
        if version not in self.data[software]:
            self.data[software][version] = []
        self.data[software][version].append(cve_info)
        self._save()

    def _save(self) -> None:
        """Persist CVE database to disk."""
        with open(self.db_path, "w") as f:
            json.dump(self.data, f, indent=2)
