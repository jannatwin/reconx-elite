import asyncio
import json
import re
import shutil
import socket
from typing import Any

import httpx


class ToolRunner:
    async def run_tool(self, command: list[str], timeout: int = 120) -> dict[str, Any]:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": "timeout",
                    "returncode": -1,
                }
            return {
                "success": process.returncode == 0,
                "stdout": stdout.decode(errors="ignore"),
                "stderr": stderr.decode(errors="ignore"),
                "returncode": process.returncode,
            }
        except Exception as e:
            return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}

    async def check_tool_available(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    async def run_subfinder(self, target: str) -> list[str]:
        if not await self.check_tool_available("subfinder"):
            return []
        result = await self.run_tool(
            ["subfinder", "-d", target, "-silent"], timeout=120
        )
        return [line.strip() for line in result["stdout"].splitlines() if line.strip()]

    async def run_httpx(self, subdomains_file: str) -> list[dict[str, Any]]:
        if not await self.check_tool_available("httpx"):
            return []
        result = await self.run_tool(
            [
                "httpx",
                "-l",
                subdomains_file,
                "-title",
                "-status-code",
                "-tech-detect",
                "-content-length",
                "-web-server",
                "-json",
                "-silent",
            ],
            timeout=120,
        )
        hosts = []
        for line in result["stdout"].splitlines():
            try:
                hosts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return hosts

    async def run_nmap(self, target: str) -> dict[str, Any]:
        if not await self.check_tool_available("nmap"):
            return {"host": target, "open_ports": []}
        result = await self.run_tool(
            [
                "nmap",
                "-p",
                "80,443,8080,8443,3000,5000,8000,9000",
                "--open",
                "-T4",
                target,
            ],
            timeout=180,
        )
        open_ports = []
        for line in result["stdout"].splitlines():
            match = re.search(r"^(\d+)/tcp\s+open", line)
            if match:
                open_ports.append(int(match.group(1)))
        return {"host": target, "open_ports": open_ports}

    async def run_nuclei(self, targets_file: str) -> list[dict[str, Any]]:
        if not await self.check_tool_available("nuclei"):
            return []
        result = await self.run_tool(
            [
                "nuclei",
                "-l",
                targets_file,
                "-severity",
                "medium,high,critical",
                "-json",
                "-silent",
            ],
            timeout=180,
        )
        findings = []
        for line in result["stdout"].splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings

    async def run_gau(self, target: str) -> list[str]:
        if not await self.check_tool_available("gau"):
            return []
        result = await self.run_tool(["gau", target, "--subs"], timeout=120)
        return [line.strip() for line in result["stdout"].splitlines() if line.strip()]

    async def check_sensitive_paths(self, base_url: str) -> list[dict[str, Any]]:
        paths = [
            "/.env",
            "/.git/config",
            "/config.json",
            "/api/docs",
            "/swagger.json",
            "/api/swagger.json",
            "/actuator",
            "/actuator/env",
            "/phpinfo.php",
            "/server-status",
            "/debug",
            "/.DS_Store",
            "/robots.txt",
            "/sitemap.xml",
        ]
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            tasks = [
                self._fetch_path(client, base_url.rstrip("/") + path) for path in paths
            ]
            return [
                result
                for result in await asyncio.gather(*tasks, return_exceptions=False)
                if result
            ]

    async def _fetch_path(
        self, client: httpx.AsyncClient, url: str
    ) -> dict[str, Any] | None:
        try:
            response = await client.get(url)
            return {
                "path": url,
                "status_code": response.status_code,
                "content_length": len(response.content),
            }
        except Exception:
            return None

    async def check_cors(self, target_url: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(
                    target_url, headers={"Origin": "https://evil-reconx.com"}
                )
            allow_origin = response.headers.get("access-control-allow-origin", "")
            allow_creds = response.headers.get("access-control-allow-credentials", "")
            return {
                "vulnerable": allow_origin == "*"
                or allow_origin == "https://evil-reconx.com",
                "details": {
                    "access_control_allow_origin": allow_origin,
                    "access_control_allow_credentials": allow_creds,
                    "status_code": response.status_code,
                },
            }
        except Exception as exc:
            return {"vulnerable": False, "details": {"error": str(exc)}}

    async def fetch_js_files(self, urls_list: list[str]) -> list[dict[str, Any]]:
        js_urls = [url for url in urls_list if url.lower().endswith(".js")]
        results: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(10)

        async def fetch(url: str) -> None:
            async with semaphore:
                try:
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        response = await client.get(url)
                    results.append({"url": url, "content": response.text})
                except Exception:
                    pass

        await asyncio.gather(*(fetch(url) for url in js_urls))
        return results

    async def check_subdomain_takeover(self, subdomain: str) -> dict[str, Any]:
        try:
            cname = socket.gethostbyname(subdomain)
        except Exception as exc:
            return {
                "vulnerable": False,
                "cname": None,
                "service": None,
                "error": str(exc),
            }
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
        ]
        service = next(
            (service for service in vulnerable_services if service in subdomain), None
        )
        return {"vulnerable": bool(service), "cname": cname, "service": service}

    async def run_whois(self, domain: str) -> dict[str, Any]:
        """Run WHOIS lookup for domain."""
        try:
            import whois

            w = whois.whois(domain)
            return {
                "success": True,
                "domain": str(w.domain_name),
                "registrar": w.registrar,
                "org": w.org,
                "country": w.country,
                "name_servers": w.name_servers,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_reverse_ip(self, ip_address: str) -> list[str]:
        """Perform reverse IP lookup using hackertarget API."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}"
                )
                if response.status_code == 200:
                    return [
                        line.strip()
                        for line in response.text.split("\n")
                        if line.strip()
                    ]
        except Exception:
            pass
        return []

    async def run_cloud_enum(self, brand_name: str) -> dict[str, list]:
        """Enumerate cloud storage buckets using brand name permutations."""
        from backend.recon.recon_pipeline import ReconPipeline

        pipeline = ReconPipeline(brand_name)
        return await pipeline.cloud_asset_discovery()
