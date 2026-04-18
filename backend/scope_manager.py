import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ScopeManager:
    """Manages discovered assets, URLs, and endpoints during scan."""

    def __init__(self, target: str):
        self.target = target
        self.subdomains: set[str] = set()
        self.urls: set[str] = set()
        self.endpoints: list[dict[str, Any]] = []
        self.js_files: list[dict[str, str]] = []
        self.parameters: dict[str, set[str]] = {}
        self.technologies: dict[str, list[str]] = {}
        self.auth_endpoints: list[str] = []
        self.api_endpoints: list[str] = []
        self.admin_endpoints: list[str] = []
        self.dev_endpoints: list[str] = []

    def add_subdomain(self, subdomain: str) -> None:
        """Add discovered subdomain."""
        self.subdomains.add(subdomain.lower())

    def add_url(self, url: str) -> None:
        """Add discovered URL."""
        self.urls.add(url)

    def add_endpoint(
        self, method: str, path: str, params: list[str] | None = None
    ) -> None:
        """Add endpoint with method and parameters."""
        self.endpoints.append(
            {
                "method": method.upper(),
                "path": path,
                "parameters": params or [],
            }
        )

    def add_js_file(self, url: str, content: str) -> None:
        """Add JS file for analysis."""
        self.js_files.append({"url": url, "content": content})

    def extract_parameters(self, url: str) -> None:
        """Extract query and path parameters from URL."""
        if "?" in url:
            query_part = url.split("?")[1]
            for param in query_part.split("&"):
                key = param.split("=")[0]
                if key:
                    self.parameters.setdefault("query", set()).add(key)

    def categorize_endpoint(self, path: str, category: str) -> None:
        """Categorize endpoint by type."""
        if category == "auth":
            self.auth_endpoints.append(path)
        elif category == "api":
            self.api_endpoints.append(path)
        elif category == "admin":
            self.admin_endpoints.append(path)
        elif category == "dev":
            self.dev_endpoints.append(path)

    def get_summary(self) -> dict[str, Any]:
        """Return a summary of discovered scope."""
        return {
            "target": self.target,
            "subdomains_count": len(self.subdomains),
            "urls_count": len(self.urls),
            "endpoints_count": len(self.endpoints),
            "js_files_count": len(self.js_files),
            "auth_endpoints": len(self.auth_endpoints),
            "api_endpoints": len(self.api_endpoints),
            "admin_endpoints": len(self.admin_endpoints),
            "dev_endpoints": len(self.dev_endpoints),
            "parameters": {k: len(v) for k, v in self.parameters.items()},
        }

    def export_scope(self) -> dict[str, Any]:
        """Export full scope as dict."""
        return {
            "target": self.target,
            "subdomains": list(self.subdomains),
            "urls": list(self.urls),
            "endpoints": self.endpoints,
            "js_files_count": len(self.js_files),
            "parameters": {k: list(v) for k, v in self.parameters.items()},
            "auth_endpoints": self.auth_endpoints,
            "api_endpoints": self.api_endpoints,
            "admin_endpoints": self.admin_endpoints,
            "dev_endpoints": self.dev_endpoints,
        }
