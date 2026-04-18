"""Misconfiguration vulnerability analyzer - Enhanced with JS key scanning."""

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class JSSecretScanner:
    """Scan JavaScript files for hardcoded API keys and secrets."""

    SECRET_PATTERNS = [
        (r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})', "API Key"),
        (
            r'(?:aws[_-]?access[_-]?key|aws[_-]?key)["\']?\s*[:=]\s*["\']([A-Z0-9]{20})',
            "AWS Access Key",
        ),
        (
            r'(?:aws[_-]?secret|aws[_-]?secret[_-]?key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})',
            "AWS Secret Key",
        ),
        (
            r'(?:github[_-]?token|gh[_-]?token)["\']?\s*[:=]\s*["\'](ghp_[a-zA-Z0-9]{36})',
            "GitHub Token",
        ),
        (
            r'(?:stripe[_-]?key|stripe[_-]?secret)["\']?\s*[:=]\s*["\'](sk_live_[a-zA-Z0-9]{24,})',
            "Stripe Key",
        ),
        (
            r'(?:google[_-]?api[_-]?key|gcp[_-]?key)["\']?\s*[:=]\s*["\'](AIza[a-zA-Z0-9_-]{35})',
            "Google API Key",
        ),
        (r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})', "Password"),
        (
            r'(?:secret|private[_-]?key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})',
            "Secret/Private Key",
        ),
        (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private Key"),
        (
            r'(?:bearer|token)["\']?\s*[:=]\s*["\'](eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})',
            "JWT Token",
        ),
    ]

    @staticmethod
    async def scan_js_file(js_url: str) -> list[dict[str, Any]]:
        """Scan a single JS file for secrets."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(js_url)
                content = response.text

                for pattern, secret_type in JSSecretScanner.SECRET_PATTERNS:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        findings.append(
                            {
                                "file": js_url,
                                "type": secret_type,
                                "match": match.group(0)[:50] + "...",
                                "severity": "CRITICAL",
                                "line_number": content[: match.start()].count("\n") + 1,
                            }
                        )
        except Exception:
            pass

        return findings


class ExposedFileChecker:
    """Check for exposed sensitive files."""

    SENSITIVE_FILES = [
        "/.git/config",
        "/.git/HEAD",
        "/.env",
        "/.env.production",
        "/config.json",
        "/package.json",
        "/docker-compose.yml",
        "/wp-config.php",
        "/.htaccess",
        "/server-status",
        "/phpinfo.php",
        "/debug/pprof",
        "/actuator/env",
        "/api/swagger.json",
        "/graphql/playground",
    ]

    @staticmethod
    async def check_exposed_files(base_url: str) -> list[dict[str, Any]]:
        """Check for exposed sensitive files."""
        findings = []

        async def check_file(path: str):
            try:
                url = f"{base_url}{path}"
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(url)
                    if response.status_code == 200 and len(response.content) > 0:
                        return {
                            "file": path,
                            "url": url,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "severity": (
                                "HIGH"
                                if path in ["/.git/config", "/.env"]
                                else "MEDIUM"
                            ),
                        }
            except Exception:
                return None

        import asyncio

        tasks = [check_file(path) for path in ExposedFileChecker.SENSITIVE_FILES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result:
                findings.append(result)

        return findings


async def analyze_misconfiguration(
    js_files: list[dict[str, str]],
    subdomains: set[str],
    tech_profile: dict[str, list[str]],
    model_router: Any,
    base_url: str = "",
) -> dict[str, Any]:
    """Analyze for misconfigurations: secrets in JS, exposed files, subdomain takeover."""
    findings = {"exposed_secrets": [], "takeover_risks": [], "exposed_files": []}

    # Scan JS files for secrets
    for js_file in js_files[:10]:  # Limit to 10 files
        js_url = js_file.get("url", "")
        if js_url:
            secrets = await JSSecretScanner.scan_js_file(js_url)
            findings["exposed_secrets"].extend(secrets)

    # Check for exposed files
    if base_url:
        exposed = await ExposedFileChecker.check_exposed_files(base_url)
        findings["exposed_files"] = exposed

    # Subdomain takeover detection
    vulnerable_services = [
        "github.io",
        "herokuapp.com",
        "s3.amazonaws.com",
        "azurewebsites.net",
        "fastly.net",
        "shopify.com",
        "zendesk.com",
        "readme.io",
        "ghost.io",
        "cloudfront.net",
    ]

    for subdomain in subdomains:
        for service in vulnerable_services:
            if service.split(".")[0] in subdomain:
                findings["takeover_risks"].append(
                    {
                        "subdomain": subdomain,
                        "service": service,
                        "test": f"Check CNAME record for dangling DNS entry",
                        "severity": "HIGH",
                    }
                )

    return {
        "vulnerability": "Misconfiguration",
        "exposed_secrets": findings["exposed_secrets"],
        "subdomain_takeover_risks": findings["takeover_risks"],
        "exposed_files": findings["exposed_files"],
        "total_risks": (
            len(findings["exposed_secrets"])
            + len(findings["takeover_risks"])
            + len(findings["exposed_files"])
        ),
    }
