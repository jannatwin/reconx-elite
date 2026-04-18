"""Phase 1: CloudHunter - Find cloud buckets via brand permutations."""

import asyncio
from typing import Any

import httpx

from backend.ai_router import AIRouter


class CloudHunter:
    """Enumerate S3, Azure Storage, and GCP buckets via brand permutations."""

    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router
        self.found_buckets = {"s3": [], "azure": [], "gcp": []}

    async def hunt_buckets(self, brand_name: str) -> dict[str, Any]:
        """Generate permutations and attempt bucket enumeration."""
        permutations = await self._generate_permutations(brand_name)

        aws_results = await self._hunt_aws_s3(permutations)
        azure_results = await self._hunt_azure_storage(permutations)
        gcp_results = await self._hunt_gcp_buckets(permutations)

        return {
            "aws_s3": aws_results,
            "azure_storage": azure_results,
            "gcp_buckets": gcp_results,
            "total_found": len(aws_results) + len(azure_results) + len(gcp_results),
        }

    async def _generate_permutations(self, brand_name: str) -> list[str]:
        """Generate bucket name variations."""
        base = brand_name.lower().replace(" ", "").replace("-", "")
        permutations = [
            base,
            f"{base}-backup",
            f"{base}-dev",
            f"{base}-prod",
            f"{base}-test",
            f"{base}-public",
            f"{base}bucket",
            f"{base}data",
            f"{base}files",
            f"{base}assets",
            f"backup-{base}",
            f"dev-{base}",
            f"prod-{base}",
            f"{base}2024",
            f"{base}2025",
        ]
        return permutations

    async def _hunt_aws_s3(self, permutations: list[str]) -> list[dict[str, Any]]:
        """Attempt to enumerate AWS S3 buckets."""
        found = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            for perm in permutations:
                try:
                    url = f"https://{perm}.s3.amazonaws.com/"
                    response = await client.head(url, follow_redirects=True)
                    if response.status_code in [200, 403]:
                        found.append(
                            {
                                "bucket_name": perm,
                                "accessible": response.status_code == 200,
                            }
                        )
                except Exception:
                    pass
        return found

    async def _hunt_azure_storage(
        self, permutations: list[str]
    ) -> list[dict[str, Any]]:
        """Attempt to enumerate Azure Storage containers."""
        found = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            for perm in permutations:
                try:
                    url = f"https://{perm}.blob.core.windows.net/"
                    response = await client.head(url, follow_redirects=True)
                    if response.status_code in [200, 403, 404]:
                        found.append(
                            {"account_name": perm, "status": response.status_code}
                        )
                except Exception:
                    pass
        return found

    async def _hunt_gcp_buckets(self, permutations: list[str]) -> list[dict[str, Any]]:
        """Attempt to enumerate GCP Storage buckets."""
        found = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            for perm in permutations:
                try:
                    url = f"https://storage.googleapis.com/{perm}/"
                    response = await client.head(url, follow_redirects=True)
                    if response.status_code in [200, 403, 404]:
                        found.append(
                            {"bucket_name": perm, "status": response.status_code}
                        )
                except Exception:
                    pass
        return found
