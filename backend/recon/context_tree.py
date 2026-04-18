"""Context Tree - JSON structure for storing target intelligence."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class ContextTree:
    """Maintains structured intelligence about the target."""

    def __init__(self, target: str, storage_dir: str = "./context_trees"):
        self.target = target
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.tree = self._initialize_tree()

    def _initialize_tree(self) -> dict[str, Any]:
        """Initialize empty context tree structure."""
        return {
            "target": self.target,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "tech_stack": {
                "backend": [],
                "frontend": [],
                "database": [],
                "cdn": [],
                "web_server": [],
                "language": [],
                "framework": [],
                "cms": [],
                "cloud_provider": [],
            },
            "api_schema": {
                "type": "unknown",  # REST, GraphQL, Both, unknown
                "endpoints": [],
                "auth_mechanism": "unknown",  # JWT, OAuth, Session, API Key, unknown
                "graphql_schema": None,
                "api_versions": [],
            },
            "known_cves": [],
            "interesting_endpoints": {
                "admin": [],
                "api": [],
                "upload": [],
                "config": [],
                "auth": [],
                "graphql": [],
                "dev": [],
            },
            "subdomains": {
                "discovered": [],
                "live": [],
                "ai_guessed": [],
            },
            "cloud_assets": {
                "s3_buckets": [],
                "azure_blobs": [],
                "gcp_storage": [],
            },
            "port_intelligence": {},
            "subsidiaries": [],
            "whois_info": {},
            "dns_records": {},
        }

    def add_tech(self, category: str, tech: str, version: str = "") -> None:
        """Add detected technology to the tree."""
        if category in self.tree["tech_stack"]:
            entry = {
                "name": tech,
                "version": version,
                "detected_at": datetime.utcnow().isoformat(),
            }
            if entry not in self.tree["tech_stack"][category]:
                self.tree["tech_stack"][category].append(entry)
            self._touch()

    def add_api_endpoint(self, endpoint: str, endpoint_type: str = "REST") -> None:
        """Add discovered API endpoint."""
        endpoint_entry = {
            "path": endpoint,
            "type": endpoint_type,
            "discovered_at": datetime.utcnow().isoformat(),
        }
        if endpoint_entry not in self.tree["api_schema"]["endpoints"]:
            self.tree["api_schema"]["endpoints"].append(endpoint_entry)

        # Categorize interesting endpoints
        self._categorize_endpoint(endpoint)
        self._touch()

    def _categorize_endpoint(self, endpoint: str) -> None:
        """Categorize endpoint into interesting categories."""
        endpoint_lower = endpoint.lower()

        if any(
            p in endpoint_lower for p in ["/admin", "/dashboard", "/manage", "/control"]
        ):
            if endpoint not in self.tree["interesting_endpoints"]["admin"]:
                self.tree["interesting_endpoints"]["admin"].append(endpoint)

        if any(p in endpoint_lower for p in ["/api/", "/graphql", "/v1", "/v2"]):
            if endpoint not in self.tree["interesting_endpoints"]["api"]:
                self.tree["interesting_endpoints"]["api"].append(endpoint)

        if any(
            p in endpoint_lower for p in ["/upload", "/file", "/image", "/document"]
        ):
            if endpoint not in self.tree["interesting_endpoints"]["upload"]:
                self.tree["interesting_endpoints"]["upload"].append(endpoint)

        if any(p in endpoint_lower for p in ["/config", "/.env", "/settings", "/env"]):
            if endpoint not in self.tree["interesting_endpoints"]["config"]:
                self.tree["interesting_endpoints"]["config"].append(endpoint)

        if any(
            p in endpoint_lower for p in ["/login", "/auth", "/oauth", "/jwt", "/token"]
        ):
            if endpoint not in self.tree["interesting_endpoints"]["auth"]:
                self.tree["interesting_endpoints"]["auth"].append(endpoint)

        if "graphql" in endpoint_lower:
            if endpoint not in self.tree["interesting_endpoints"]["graphql"]:
                self.tree["interesting_endpoints"]["graphql"].append(endpoint)

        if any(p in endpoint_lower for p in ["/dev", "/staging", "/test", "/debug"]):
            if endpoint not in self.tree["interesting_endpoints"]["dev"]:
                self.tree["interesting_endpoints"]["dev"].append(endpoint)

    def add_subdomain(
        self, subdomain: str, is_live: bool = False, is_ai_guessed: bool = False
    ) -> None:
        """Add discovered subdomain."""
        if subdomain not in self.tree["subdomains"]["discovered"]:
            self.tree["subdomains"]["discovered"].append(subdomain)

        if is_live and subdomain not in self.tree["subdomains"]["live"]:
            self.tree["subdomains"]["live"].append(subdomain)

        if is_ai_guessed and subdomain not in self.tree["subdomains"]["ai_guessed"]:
            self.tree["subdomains"]["ai_guessed"].append(subdomain)

        self._touch()

    def add_cloud_asset(
        self, provider: str, asset_url: str, permissions: dict = None
    ) -> None:
        """Add discovered cloud asset."""
        asset_entry = {
            "url": asset_url,
            "permissions": permissions or {},
            "discovered_at": datetime.utcnow().isoformat(),
        }

        if (
            provider == "s3"
            and asset_entry not in self.tree["cloud_assets"]["s3_buckets"]
        ):
            self.tree["cloud_assets"]["s3_buckets"].append(asset_entry)
        elif (
            provider == "azure"
            and asset_entry not in self.tree["cloud_assets"]["azure_blobs"]
        ):
            self.tree["cloud_assets"]["azure_blobs"].append(asset_entry)
        elif (
            provider == "gcp"
            and asset_entry not in self.tree["cloud_assets"]["gcp_storage"]
        ):
            self.tree["cloud_assets"]["gcp_storage"].append(asset_entry)

        self._touch()

    def add_port_info(self, host: str, ports: list[dict]) -> None:
        """Add port intelligence for a host."""
        self.tree["port_intelligence"][host] = {
            "ports": ports,
            "scanned_at": datetime.utcnow().isoformat(),
        }
        self._touch()

    def add_cve(self, cve_data: dict) -> None:
        """Add known CVE for detected technology."""
        if cve_data not in self.tree["known_cves"]:
            self.tree["known_cves"].append(cve_data)
            self._touch()

    def set_api_type(self, api_type: str) -> None:
        """Set detected API type."""
        if api_type in ["REST", "GraphQL", "Both", "unknown"]:
            self.tree["api_schema"]["type"] = api_type
            self._touch()

    def set_auth_mechanism(self, auth_type: str) -> None:
        """Set detected authentication mechanism."""
        if auth_type in ["JWT", "OAuth", "Session", "API Key", "unknown"]:
            self.tree["api_schema"]["auth_mechanism"] = auth_type
            self._touch()

    def add_subsidiary(self, subsidiary_data: dict) -> None:
        """Add subsidiary/acquired company."""
        if subsidiary_data not in self.tree["subsidiaries"]:
            self.tree["subsidiaries"].append(subsidiary_data)
            self._touch()

    def set_whois_info(self, whois_data: dict) -> None:
        """Set WHOIS information."""
        self.tree["whois_info"] = whois_data
        self._touch()

    def set_dns_records(self, dns_data: dict) -> None:
        """Set DNS records."""
        self.tree["dns_records"] = dns_data
        self._touch()

    def _touch(self) -> None:
        """Update timestamp."""
        self.tree["updated_at"] = datetime.utcnow().isoformat()

    def save(self, filename: str = None) -> Path:
        """Save context tree to JSON file."""
        if filename is None:
            filename = f'{self.target.replace(".", "_")}_context.json'

        filepath = self.storage_dir / filename
        with open(filepath, "w") as f:
            json.dump(self.tree, f, indent=2, default=str)

        return filepath

    def load(self, filename: str = None) -> dict[str, Any]:
        """Load context tree from JSON file."""
        if filename is None:
            filename = f'{self.target.replace(".", "_")}_context.json'

        filepath = self.storage_dir / filename
        if filepath.exists():
            with open(filepath, "r") as f:
                self.tree = json.load(f)

        return self.tree

    def get_tree(self) -> dict[str, Any]:
        """Get the complete context tree."""
        return self.tree

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of the context tree."""
        return {
            "target": self.target,
            "subdomains_count": len(self.tree["subdomains"]["discovered"]),
            "live_hosts_count": len(self.tree["subdomains"]["live"]),
            "tech_count": sum(len(v) for v in self.tree["tech_stack"].values()),
            "api_endpoints_count": len(self.tree["api_schema"]["endpoints"]),
            "cloud_assets_count": sum(
                len(v) for v in self.tree["cloud_assets"].values()
            ),
            "cves_count": len(self.tree["known_cves"]),
            "interesting_endpoints": {
                k: len(v) for k, v in self.tree["interesting_endpoints"].items()
            },
        }
