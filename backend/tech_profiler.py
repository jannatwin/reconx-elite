import re
from typing import Any


class TechProfiler:
    """Deep technology fingerprinting module for detected tech stacks."""

    def __init__(self):
        self.detected_techs = {
            "languages": [],
            "frameworks": [],
            "cms": [],
            "cloud_providers": [],
            "auth_methods": [],
            "databases": [],
            "frontend_frameworks": [],
        }

    async def profile_target(
        self, content: str, headers: dict[str, str], urls: list[str]
    ) -> dict[str, Any]:
        """Profile a target for technology stack."""
        self._analyze_headers(headers)
        self._analyze_content(content)
        self._analyze_urls(urls)
        return self.detected_techs

    def _analyze_headers(self, headers: dict[str, str]) -> None:
        """Extract tech from response headers."""
        server = headers.get("server", "").lower()
        if "nginx" in server:
            self.detected_techs["frameworks"].append("Nginx")
        if "apache" in server:
            self.detected_techs["frameworks"].append("Apache")
        if "python" in server or "django" in server or "flask" in server:
            self.detected_techs["languages"].append("Python")
        if "node" in server or "express" in server:
            self.detected_techs["languages"].append("Node.js")
        if "php" in server:
            self.detected_techs["languages"].append("PHP")
        if "asp" in server or "dotnet" in server:
            self.detected_techs["languages"].append("C#/.NET")

        powered_by = headers.get("x-powered-by", "").lower()
        if "express" in powered_by:
            self.detected_techs["frameworks"].append("Express.js")
        if "django" in powered_by:
            self.detected_techs["frameworks"].append("Django")
        if "laravel" in powered_by:
            self.detected_techs["frameworks"].append("Laravel")

    def _analyze_content(self, content: str) -> None:
        """Extract tech signals from HTML/JS content."""
        content_lower = content.lower()

        if "react" in content_lower or "react.js" in content_lower:
            self.detected_techs["frontend_frameworks"].append("React")
        if "vue" in content_lower or "vue.js" in content_lower:
            self.detected_techs["frontend_frameworks"].append("Vue.js")
        if "angular" in content_lower:
            self.detected_techs["frontend_frameworks"].append("Angular")
        if "graphql" in content_lower:
            self.detected_techs["frameworks"].append("GraphQL")
        if "jwt" in content_lower:
            self.detected_techs["auth_methods"].append("JWT")
        if "oauth" in content_lower:
            self.detected_techs["auth_methods"].append("OAuth")
        if "saml" in content_lower:
            self.detected_techs["auth_methods"].append("SAML")

        aws_patterns = [
            r"amazonaws\.com",
            r"s3\.aws\.amazon\.com",
            r"elasticbeanstalk",
            r"cloudfront\.net",
        ]
        if any(re.search(p, content, re.IGNORECASE) for p in aws_patterns):
            self.detected_techs["cloud_providers"].append("AWS")

        azure_patterns = [
            r"azurewebsites\.net",
            r"blob\.core\.windows\.net",
            r"table\.core\.windows\.net",
        ]
        if any(re.search(p, content, re.IGNORECASE) for p in azure_patterns):
            self.detected_techs["cloud_providers"].append("Azure")

        gcp_patterns = [r"appspot\.com", r"googleapis\.com", r"cloudflare"]
        if any(re.search(p, content, re.IGNORECASE) for p in gcp_patterns):
            self.detected_techs["cloud_providers"].append("GCP")

    def _analyze_urls(self, urls: list[str]) -> None:
        """Extract tech signals from URL patterns."""
        for url in urls:
            if "/wp-admin" in url or "/wp-content" in url:
                self.detected_techs["cms"].append("WordPress")
            if "/joomla" in url or "/component" in url:
                self.detected_techs["cms"].append("Joomla")
            if "/drupal" in url or "/sites/all" in url:
                self.detected_techs["cms"].append("Drupal")

            if "/graphql" in url:
                self.detected_techs["frameworks"].append("GraphQL")
            if "/api/v" in url and not "graphql" in url:
                self.detected_techs["frameworks"].append("REST API")

    def get_profile(self) -> dict[str, Any]:
        """Return the accumulated tech profile."""
        deduplicated = {}
        for key, values in self.detected_techs.items():
            deduplicated[key] = list(set(values))
        return deduplicated

    def has_high_value_keywords(self) -> dict[str, bool]:
        """Return flags for high-value attack vectors."""
        profile = self.get_profile()
        content_str = " ".join(
            str(v) for vals in profile.values() for v in vals
        ).lower()
        return {
            "has_graphql": "graphql" in content_str,
            "has_jwt": "jwt" in content_str,
            "has_aws": "aws" in content_str,
            "has_azure": "azure" in content_str,
            "has_checkout": True,
            "has_rest_api": "rest api" in content_str,
            "has_oauth": "oauth" in content_str,
        }
