"""Enhanced Reconnaissance Pipeline - Class-based recon engine."""

import asyncio
import logging
import re
from typing import Any

import httpx

from backend.tool_runner import ToolRunner
from backend.recon.context_tree import ContextTree

logger = logging.getLogger(__name__)


class ReconPipeline:
    """Class-based reconnaissance engine for comprehensive asset discovery."""

    def __init__(self, target: str, ai_router=None):
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = ToolRunner()
        self.context_tree = ContextTree(target)
        self.brand_name = self._extract_brand_name(target)

    def _extract_brand_name(self, target: str) -> str:
        """Extract brand name from target domain for cloud permutation."""
        # Remove TLD and common prefixes
        brand = target.split(".")[0]
        brand = re.sub(r"^(www|app|api|dev|staging)-?", "", brand)
        return brand.lower()

    async def execute_full_recon(self) -> dict[str, Any]:
        """Execute complete reconnaissance pipeline."""
        logger.info(f"Starting full recon for {self.target}")

        # Phase 1: Subdomain Discovery
        await self.recursive_subdomain_discovery()

        # Phase 2: Cloud Asset Discovery
        await self.cloud_asset_discovery()

        # Phase 3: Port Intelligence
        await self.port_intelligence()

        # Phase 4: Acquisition Mapping
        await self.acquisition_mapping()

        # Save context tree
        self.context_tree.save()

        return self.context_tree.get_summary()

    async def recursive_subdomain_discovery(self, depth: int = 3) -> list[str]:
        """
        Recursive subdomain enumeration going 3 levels deep.
        Uses AI to guess potential hidden subdomains.
        """
        logger.info(f"Starting recursive subdomain discovery (depth={depth})")

        all_subdomains = set()

        # Level 1: Initial discovery with subfinder
        level1_subs = await self.tool_runner.run_subfinder(self.target)
        all_subdomains.update(level1_subs)

        # Add to context tree
        for sub in level1_subs:
            self.context_tree.add_subdomain(sub)

        logger.info(f"Level 1: Found {len(level1_subs)} subdomains")

        # Level 2-3: Recursive discovery on discovered subdomains
        for current_depth in range(2, depth + 1):
            if current_depth > 3:
                break

            new_subs = set()
            # Use wildcards on discovered subdomains
            for sub in list(all_subdomains)[:10]:  # Limit for performance
                deeper_subs = await self.tool_runner.run_subfinder(sub)
                new_subs.update(deeper_subs)

            all_subdomains.update(new_subs)
            for sub in new_subs:
                self.context_tree.add_subdomain(sub)

            logger.info(
                f"Level {current_depth}: Found {len(new_subs)} additional subdomains"
            )

            if not new_subs:
                break

        # AI-powered subdomain guessing
        if self.ai_router:
            guessed_subs = await self._ai_guess_subdomains(list(all_subdomains))
            all_subdomains.update(guessed_subs)
            for sub in guessed_subs:
                self.context_tree.add_subdomain(sub, is_ai_guessed=True)
            logger.info(f"AI guessed {len(guessed_subs)} potential subdomains")

        # Check which subdomains are live
        live_subs = await self._check_live_hosts(list(all_subdomains))
        for sub in live_subs:
            self.context_tree.add_subdomain(sub, is_live=True)

        logger.info(f"Total subdomains: {len(all_subdomains)}, Live: {len(live_subs)}")
        return list(all_subdomains)

    async def _ai_guess_subdomains(self, existing_subs: list[str]) -> list[str]:
        """Use AI to guess potential hidden subdomains based on naming patterns."""
        if not self.ai_router:
            return []

        # Analyze existing patterns
        prefixes = [
            "dev",
            "staging",
            "test",
            "api",
            "admin",
            "internal",
            "corp",
            "vpn",
            "mail",
            "ftp",
        ]
        common_patterns = []

        for sub in existing_subs:
            parts = sub.replace(self.target, "").rstrip(".").split(".")
            if parts:
                common_patterns.append(parts[0])

        # Ask AI to generate likely subdomains
        prompt = f"""Based on these discovered subdomains for {self.target}:
{', '.join(existing_subs[:20])}

Common prefixes found: {', '.join(set(common_patterns))}

Generate 10 likely subdomain names that might exist but weren't discovered. 
Focus on common patterns like: dev-, staging-, api-, admin-, internal-, test-
Return only subdomain names, one per line, no explanations."""

        try:
            result = await self.ai_router.call_model(
                "orchestrator", prompt, max_tokens=512
            )
            output = result.get("output", "")

            # Parse AI output
            guessed = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line and "." in line:
                    # Validate it's a subdomain of target
                    if line.endswith(self.target) or self.target in line:
                        guessed.append(line)
                    else:
                        guessed.append(f"{line}.{self.target}")

            return guessed[:10]
        except Exception as e:
            logger.error(f"AI subdomain guessing failed: {e}")
            return []

    async def _check_live_hosts(self, subdomains: list[str]) -> list[str]:
        """Check which subdomains are live using httpx."""
        logger.info(f"Checking {len(subdomains)} subdomains for live hosts")

        # Write subdomains to temp file for httpx
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(subdomains))
            temp_file = f.name

        # Run httpx
        live_hosts = await self.tool_runner.run_httpx(temp_file)

        # Extract live URLs
        live_urls = []
        for host in live_hosts:
            if isinstance(host, dict):
                url = host.get("input") or host.get("url")
                if url:
                    live_urls.append(url)
            elif isinstance(host, str):
                live_urls.append(host)

        import os

        try:
            os.unlink(temp_file)
        except:
            pass

        return live_urls

    async def cloud_asset_discovery(self) -> dict[str, list]:
        """
        Discover cloud assets by permutating brand name.
        Check S3 buckets, Azure Blobs, GCP storage.
        """
        logger.info(f"Starting cloud asset discovery for brand: {self.brand_name}")

        cloud_assets = {
            "s3": [],
            "azure": [],
            "gcp": [],
        }

        # Generate permutations
        permutations = self._generate_cloud_permutations()

        # Check S3 buckets
        s3_tasks = [self._check_s3_bucket(perm) for perm in permutations]
        s3_results = await asyncio.gather(*s3_tasks, return_exceptions=True)

        for result in s3_results:
            if isinstance(result, dict) and result.get("exists"):
                cloud_assets["s3"].append(result)
                self.context_tree.add_cloud_asset(
                    "s3", result["url"], result.get("permissions")
                )

        # Check Azure Blobs
        azure_tasks = [self._check_azure_blob(perm) for perm in permutations]
        azure_results = await asyncio.gather(*azure_tasks, return_exceptions=True)

        for result in azure_results:
            if isinstance(result, dict) and result.get("exists"):
                cloud_assets["azure"].append(result)
                self.context_tree.add_cloud_asset(
                    "azure", result["url"], result.get("permissions")
                )

        # Check GCP Storage
        gcp_tasks = [self._check_gcp_storage(perm) for perm in permutations]
        gcp_results = await asyncio.gather(*gcp_tasks, return_exceptions=True)

        for result in gcp_results:
            if isinstance(result, dict) and result.get("exists"):
                cloud_assets["gcp"].append(result)
                self.context_tree.add_cloud_asset(
                    "gcp", result["url"], result.get("permissions")
                )

        total_found = sum(len(v) for v in cloud_assets.values())
        logger.info(f"Cloud discovery complete: Found {total_found} assets")

        return cloud_assets

    def _generate_cloud_permutations(self) -> list[str]:
        """Generate cloud storage name permutations."""
        brand = self.brand_name
        permutations = [
            brand,
            f"{brand}-assets",
            f"{brand}-storage",
            f"{brand}-files",
            f"{brand}-data",
            f"{brand}-backups",
            f"{brand}-uploads",
            f"{brand}-media",
            f"{brand}-static",
            f"{brand}-cdn",
            f"{brand}-prod",
            f"{brand}-production",
            f"{brand}-dev",
            f"{brand}-staging",
            f"{brand}-test",
            f"{brand}-public",
            f"{brand}-private",
            f"{brand}-internal",
            f"assets-{brand}",
            f"storage-{brand}",
        ]
        return permutations

    async def _check_s3_bucket(self, bucket_name: str) -> dict[str, Any]:
        """Check if S3 bucket exists and test permissions."""
        url = f"https://{bucket_name}.s3.amazonaws.com"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Check if bucket exists
                response = await client.get(url)

                if response.status_code == 200:
                    # Bucket exists and is listable
                    return {
                        "exists": True,
                        "url": url,
                        "bucket_name": bucket_name,
                        "permissions": {"ListBucket": True},
                        "status_code": response.status_code,
                    }
                elif response.status_code == 403:
                    # Bucket exists but not listable
                    return {
                        "exists": True,
                        "url": url,
                        "bucket_name": bucket_name,
                        "permissions": {"ListBucket": False},
                        "status_code": response.status_code,
                    }
                else:
                    return {"exists": False, "url": url}
        except Exception:
            return {"exists": False, "url": url}

    async def _check_azure_blob(self, container_name: str) -> dict[str, Any]:
        """Check if Azure Blob container exists."""
        url = f"https://{container_name}.blob.core.windows.net"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)

                if response.status_code in [200, 403]:
                    return {
                        "exists": True,
                        "url": url,
                        "container_name": container_name,
                        "permissions": {"ListContainers": response.status_code == 200},
                        "status_code": response.status_code,
                    }
                else:
                    return {"exists": False, "url": url}
        except Exception:
            return {"exists": False, "url": url}

    async def _check_gcp_storage(self, bucket_name: str) -> dict[str, Any]:
        """Check if GCP Storage bucket exists."""
        url = f"https://storage.googleapis.com/{bucket_name}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    return {
                        "exists": True,
                        "url": url,
                        "bucket_name": bucket_name,
                        "permissions": {"ListBucket": True},
                        "status_code": response.status_code,
                    }
                elif response.status_code == 403:
                    return {
                        "exists": True,
                        "url": url,
                        "bucket_name": bucket_name,
                        "permissions": {"ListBucket": False},
                        "status_code": response.status_code,
                    }
                else:
                    return {"exists": False, "url": url}
        except Exception:
            return {"exists": False, "url": url}

    async def port_intelligence(self) -> dict[str, list]:
        """
        Scan top 1000 ports + common dev ports.
        Returns open ports per host.
        """
        logger.info("Starting port intelligence scan")

        # Get live hosts from context tree
        live_hosts = self.context_tree.tree["subdomains"]["live"]

        if not live_hosts:
            # If no live hosts yet, check subdomains
            all_subs = self.context_tree.tree["subdomains"]["discovered"]
            live_hosts = await self._check_live_hosts(
                all_subs[:10]
            )  # Limit for performance

        port_results = {}

        # Common dev ports to scan
        dev_ports = [3000, 5000, 8000, 8080, 8443, 9000, 4000, 8888, 3001, 5001]

        # Scan each host
        for host in live_hosts[:10]:  # Limit for performance
            # Extract hostname from URL
            hostname = (
                host.replace("http://", "")
                .replace("https://", "")
                .split("/")[0]
                .split(":")[0]
            )

            # Run nmap scan
            nmap_result = await self.tool_runner.run_nmap(hostname)

            # Add dev ports
            all_ports = nmap_result.get("open_ports", [])

            # Check dev ports individually
            dev_port_tasks = [self._check_port(hostname, port) for port in dev_ports]
            dev_port_results = await asyncio.gather(
                *dev_port_tasks, return_exceptions=True
            )

            for result in dev_port_results:
                if isinstance(result, dict) and result.get("open"):
                    all_ports.append(result["port"])

            port_results[hostname] = all_ports
            self.context_tree.add_port_info(
                hostname, [{"port": p, "service": "unknown"} for p in all_ports]
            )

        logger.info(f"Port scan complete: {len(port_results)} hosts scanned")
        return port_results

    async def _check_port(self, host: str, port: int) -> dict[str, Any]:
        """Check if a specific port is open."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            writer.close()
            await writer.wait_closed()
            return {"port": port, "open": True}
        except Exception:
            return {"port": port, "open": False}

    async def acquisition_mapping(self) -> list[dict[str, Any]]:
        """
        Identify subsidiary domains via WHOIS and reverse-IP lookups.
        """
        logger.info("Starting acquisition mapping")

        subsidiaries = []

        # WHOIS lookup
        whois_info = await self._whois_lookup(self.target)
        if whois_info:
            self.context_tree.set_whois_info(whois_info)

            # Extract organization name
            org = whois_info.get("org_name", "")
            if org:
                subsidiaries.append(
                    {
                        "type": "whois",
                        "organization": org,
                        "target": self.target,
                    }
                )

        # Reverse IP lookup
        reverse_ip_results = await self._reverse_ip_lookup(self.target)
        for result in reverse_ip_results:
            subsidiaries.append(
                {
                    "type": "reverse_ip",
                    "domain": result,
                    "target": self.target,
                }
            )
            self.context_tree.add_subdomain(result)

        logger.info(
            f"Acquisition mapping complete: Found {len(subsidiaries)} related entities"
        )
        return subsidiaries

    async def _whois_lookup(self, domain: str) -> dict[str, Any]:
        """Perform WHOIS lookup."""
        try:
            import whois

            w = whois.whois(domain)

            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "org_name": w.org,
                "country": w.country,
                "name_servers": w.name_servers,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return {}

    async def _reverse_ip_lookup(self, domain: str) -> list[str]:
        """Perform reverse IP lookup to find other domains on same server."""
        try:
            import socket
            import dns.resolver

            # Get IP address
            ip = socket.gethostbyname(domain)

            # Use API for reverse IP (viewdns.info alternative)
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Using hackertarget.com API (free, no key required)
                response = await client.get(
                    f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
                )

                if response.status_code == 200:
                    domains = [
                        line.strip()
                        for line in response.text.split("\n")
                        if line.strip()
                    ]
                    return domains
        except Exception as e:
            logger.error(f"Reverse IP lookup failed for {domain}: {e}")

        return []
