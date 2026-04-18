"""Phase 1: AcquisitionMapper - Find subsidiary companies and related domains."""

import asyncio
from typing import Any

import httpx

from backend.ai_router import AIRouter


class AcquisitionMapper:
    """Search WHOIS, public records, and company databases for related entities."""

    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router
        self.found_subsidiaries = []

    async def map_acquisitions(self, domain: str) -> dict[str, Any]:
        """Find subsidiary companies and related domains."""
        # Extract company name from domain
        company_name = await self._extract_company_name(domain)

        # Search multiple sources
        whois_results = await self._search_whois(domain)
        subsidiary_results = await self._search_subsidiaries(company_name)
        related_domains = await self._search_related_domains(domain)

        return {
            "company_name": company_name,
            "primary_domain": domain,
            "whois_contacts": whois_results,
            "subsidiaries": subsidiary_results,
            "related_domains": related_domains,
            "total_entities": len(subsidiary_results) + len(related_domains),
        }

    async def _extract_company_name(self, domain: str) -> str:
        """Extract company name from domain using AI."""
        prompt = f"Extract the company name from this domain: {domain}. Return ONLY the company name."
        result = await self.ai_router.call_model(
            "fast_classifier", prompt, max_tokens=50
        )
        return result.get("output", "unknown").strip().split("\n")[0]

    async def _search_whois(self, domain: str) -> list[dict[str, Any]]:
        """Query WHOIS data (mocked for now)."""
        # In production, integrate with WHOIS database
        return [
            {"registrant": "Information typically found in WHOIS"},
            {"registrar": "Check via WHOIS API"},
            {"created": "Date from WHOIS"},
        ]

    async def _search_subsidiaries(self, company_name: str) -> list[str]:
        """Search for subsidiary companies."""
        prompt = f"List major subsidiaries and companies owned by {company_name}. Format as comma-separated list."
        result = await self.ai_router.call_model(
            "primary_analyst", prompt, max_tokens=200
        )
        output = result.get("output", "")
        if output:
            return [s.strip() for s in output.split(",")]
        return []

    async def _search_related_domains(self, primary_domain: str) -> list[str]:
        """Find related domains via DNS and certificates."""
        # This would integrate with certificate transparency logs, DNS records, etc.
        # For now, return framework for integration
        related = []
        base_name = primary_domain.split(".")[0]

        # Try common variations
        tlds = ["com", "io", "net", "org", "co", "dev", "app", "ai"]
        for tld in tlds:
            test_domain = f"{base_name}.{tld}"
            if test_domain != primary_domain:
                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        response = await client.head(
                            f"https://{test_domain}", follow_redirects=True
                        )
                        if response.status_code < 500:
                            related.append(test_domain)
                except Exception:
                    pass

        return related
