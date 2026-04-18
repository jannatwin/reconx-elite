"""
ContextTree - Phase 2 of Agentic Multi-Model Vulnerability Research Engine
Creates JSON structure storing Tech Stack, API Schema, Auth Mechanism, and CVEs
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path

from ai_router import AIRouter
from tech_profiler import TechProfiler
from phase_2_api_mapper import APIMapper
from phase_2_cve_database import CVEDatabase
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


@dataclass
class TechnologyComponent:
    name: str
    category: str  # backend, frontend, database, framework, etc.
    version: Optional[str] = None
    confidence: float = 0.0
    source: str = "unknown"
    cves: List[Dict[str, Any]] = None


@dataclass
class APIEndpoint:
    url: str
    method: str
    parameters: List[Dict[str, Any]]
    auth_required: bool = False
    content_type: str = "application/json"
    api_type: str = "REST"  # REST, GraphQL, WebSocket
    description: str = ""


@dataclass
class AuthenticationMechanism:
    type: str  # JWT, OAuth, Session, API Key, etc.
    location: str  # Header, Cookie, Query, Body
    confidence: float = 0.0
    details: Dict[str, Any] = None


@dataclass
class InterestingEndpoint:
    url: str
    category: str  # admin, api, graphql, upload, config, env, etc.
    risk_level: str  # low, medium, high, critical
    accessible: bool = False
    findings: List[str] = None


class ContextTree:
    """Technology profiler and context tree builder"""

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager

        # Initialize specialized components
        self.tech_profiler = TechProfiler(session_id, ws_manager)
        self.api_mapper = APIMapper(session_id, ws_manager)
        self.cve_database = CVEDatabase(session_id, ws_manager)

        # Storage for context data
        self.tech_stack: List[TechnologyComponent] = []
        self.api_endpoints: List[APIEndpoint] = []
        self.auth_mechanisms: List[AuthenticationMechanism] = []
        self.interesting_endpoints: List[InterestingEndpoint] = []
        self.known_cves: Dict[str, List[Dict[str, Any]]] = {}

        # Known interesting endpoint patterns
        self.interesting_patterns = {
            "admin": ["/admin", "/administrator", "/admin.php", "/admin/login"],
            "api": ["/api", "/api/v1", "/api/v2", "/rest", "/rest/api"],
            "graphql": ["/graphql", "/graphiql", "/playground", "/graphql.php"],
            "upload": ["/upload", "/uploads", "/file/upload", "/api/upload"],
            "config": ["/config", "/configuration", "/settings", "/env"],
            "env": ["/env", "/.env", "/environment", "/config/env"],
            "dev": ["/dev", "/development", "/test", "/staging"],
            "debug": ["/debug", "/phpinfo", "/info", "/status"],
            "backup": ["/backup", "/backups", "/dump", "/export"],
            "logs": ["/logs", "/log", "/access.log", "/error.log"],
        }

    async def build_context_tree(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive context tree from reconnaissance results"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Building technology context tree...",
            phase="context_tree",
        )

        try:
            # Phase 2.1: Technology Stack Profiling
            await self._profile_technology_stack(recon_results)

            # Phase 2.2: API Schema Mapping
            await self._map_api_schema(recon_results)

            # Phase 2.3: Authentication Mechanism Detection
            await self._detect_authentication_mechanisms(recon_results)

            # Phase 2.4: Interesting Endpoint Mapping
            await self._map_interesting_endpoints(recon_results)

            # Phase 2.5: CVE Correlation
            await self._correlate_cves()

            # Compile context tree
            context_tree = self._compile_context_tree()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Context tree built: {len(self.tech_stack)} technologies, "
                f"{len(self.api_endpoints)} endpoints, {len(self.interesting_endpoints)} interesting targets",
                phase="context_tree",
            )

            return context_tree

        except Exception as e:
            logger.error(f"Context tree building failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Context tree building failed: {str(e)}",
                phase="context_tree",
            )
            raise

    async def _profile_technology_stack(self, recon_results: Dict[str, Any]) -> None:
        """Profile the technology stack using AI analysis"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Profiling technology stack...",
            phase="tech_profiling",
        )

        # Get live hosts from reconnaissance results
        live_hosts = []
        for subdomain_data in recon_results.get("subdomains", {}).get("results", []):
            subdomain = subdomain_data.get("subdomain", "")
            if subdomain:
                live_hosts.append(subdomain)

        # Analyze each host for technology indicators
        for host in live_hosts[:20]:  # Limit to prevent excessive analysis
            try:
                await self._analyze_host_technology(host)
            except Exception as e:
                logger.debug(f"Technology analysis failed for {host}: {e}")

        # Use AI to enhance technology detection
        await self._ai_enhanced_tech_detection()

    async def _analyze_host_technology(self, host: str) -> None:
        """Analyze a single host for technology indicators"""
        try:
            # Get HTTP headers and content
            result = await self.tool_runner.run_tool("http_analyze", host)

            if not result:
                return

            # Analyze headers for technology indicators
            headers = result.get("headers", {})
            content = result.get("content", "")

            # Extract technologies from headers
            tech_indicators = self._extract_tech_from_headers(headers)

            # Extract technologies from content
            content_indicators = self._extract_tech_from_content(content)

            # Combine indicators
            all_indicators = tech_indicators + content_indicators

            # Add to tech stack
            for indicator in all_indicators:
                tech_component = TechnologyComponent(
                    name=indicator.get("name", ""),
                    category=indicator.get("category", "unknown"),
                    version=indicator.get("version"),
                    confidence=indicator.get("confidence", 0.5),
                    source=(
                        f"header:{host}"
                        if indicator in tech_indicators
                        else f"content:{host}"
                    ),
                )

                # Avoid duplicates
                if not any(
                    t.name == tech_component.name
                    and t.category == tech_component.category
                    for t in self.tech_stack
                ):
                    self.tech_stack.append(tech_component)

        except Exception as e:
            logger.debug(f"Host technology analysis failed for {host}: {e}")

    def _extract_tech_from_headers(
        self, headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Extract technology indicators from HTTP headers"""
        indicators = []

        # Common technology headers
        tech_headers = {
            "server": "backend",
            "x-powered-by": "backend",
            "x-aspnet-version": "backend",
            "x-aspnetmvc-version": "backend",
            "x-drupal-cache": "cms",
            "x-generator": "cms",
            "x-shopify-storefront-renderer": "ecommerce",
            "x-woocommerce-version": "ecommerce",
            "x-wordpress": "cms",
        }

        for header, value in headers.items():
            header_lower = header.lower()

            if header_lower in tech_headers:
                indicators.append(
                    {
                        "name": value,
                        "category": tech_headers[header_lower],
                        "confidence": 0.8,
                        "version": None,
                    }
                )

            # Look for version information
            version_match = re.search(r"(\d+\.\d+(\.\d+)?)", value)
            if version_match:
                indicators.append(
                    {
                        "name": header,
                        "category": "version_info",
                        "confidence": 0.6,
                        "version": version_match.group(1),
                    }
                )

        return indicators

    def _extract_tech_from_content(self, content: str) -> List[Dict[str, Any]]:
        """Extract technology indicators from page content"""
        indicators = []

        # Common technology signatures
        tech_signatures = {
            # JavaScript frameworks
            r"react\.js": {"name": "React", "category": "frontend"},
            r"vue\.js": {"name": "Vue.js", "category": "frontend"},
            r"angular\.js": {"name": "Angular", "category": "frontend"},
            r"jquery": {"name": "jQuery", "category": "frontend"},
            # Backend frameworks
            r"django": {"name": "Django", "category": "backend"},
            r"flask": {"name": "Flask", "category": "backend"},
            r"express": {"name": "Express.js", "category": "backend"},
            r"spring": {"name": "Spring", "category": "backend"},
            # CMS
            r"wordpress": {"name": "WordPress", "category": "cms"},
            r"drupal": {"name": "Drupal", "category": "cms"},
            r"joomla": {"name": "Joomla", "category": "cms"},
            # Database
            r"mysql": {"name": "MySQL", "category": "database"},
            r"postgresql": {"name": "PostgreSQL", "category": "database"},
            r"mongodb": {"name": "MongoDB", "category": "database"},
        }

        for pattern, tech_info in tech_signatures.items():
            if re.search(pattern, content, re.IGNORECASE):
                indicators.append(
                    {
                        "name": tech_info["name"],
                        "category": tech_info["category"],
                        "confidence": 0.7,
                        "version": None,
                    }
                )

        return indicators

    async def _ai_enhanced_tech_detection(self) -> None:
        """Use AI to enhance technology detection"""
        if not self.tech_stack:
            return

        # Create AI prompt for enhanced analysis
        tech_summary = "\n".join([f"{t.name} ({t.category})" for t in self.tech_stack])

        prompt = f"""
        Analyze the following detected technologies for {self.target} and provide enhanced insights:
        
        Detected Technologies:
        {tech_summary}
        
        Based on these technologies, identify:
        1. Likely architecture patterns (microservices, monolith, serverless)
        2. Additional technologies that might be present but not detected
        3. Potential security implications of this tech stack
        4. Common vulnerabilities associated with this combination
        
        Return as JSON with keys: architecture, additional_techs, security_implications, common_vulnerabilities
        """

        try:
            result = await self.ai_router.call_model(
                role="deep_analyst", prompt=prompt, max_tokens=800
            )

            if result.get("output"):
                # Parse AI analysis
                try:
                    ai_analysis = json.loads(result["output"])

                    # Add additional technologies suggested by AI
                    for tech_name in ai_analysis.get("additional_techs", []):
                        if not any(t.name == tech_name for t in self.tech_stack):
                            self.tech_stack.append(
                                TechnologyComponent(
                                    name=tech_name,
                                    category="ai_suggested",
                                    confidence=0.4,
                                    source="ai_enhancement",
                                )
                            )

                except json.JSONDecodeError:
                    logger.warning("AI tech analysis response not valid JSON")

        except Exception as e:
            logger.error(f"AI enhanced tech detection failed: {e}")

    async def _map_api_schema(self, recon_results: Dict[str, Any]) -> None:
        """Map API endpoints and schemas"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Mapping API schema...", phase="api_mapping"
        )

        # Use existing API mapper
        api_results = await self.api_mapper.map_apis(self.target, recon_results)

        # Convert to APIEndpoint objects
        for api_data in api_results:
            endpoint = APIEndpoint(
                url=api_data.get("url", ""),
                method=api_data.get("method", "GET"),
                parameters=api_data.get("parameters", []),
                auth_required=api_data.get("auth_required", False),
                content_type=api_data.get("content_type", "application/json"),
                api_type=api_data.get("api_type", "REST"),
                description=api_data.get("description", ""),
            )

            self.api_endpoints.append(endpoint)

        # AI-enhanced API discovery
        await self._ai_api_discovery()

    async def _ai_api_discovery(self) -> None:
        """Use AI to discover additional API endpoints"""
        prompt = f"""
        Based on the target {self.target}, predict potential API endpoints that might exist but weren't discovered.
        
        Consider common API patterns:
        - Authentication: /auth/login, /auth/register, /auth/refresh
        - User management: /users, /users/{id}, /profile
        - Data operations: /data, /records, /items
        - Admin functions: /admin/users, /admin/settings
        - File operations: /files, /upload, /download
        - Search: /search, /api/search
        - Webhooks: /webhooks, /hooks
        
        Generate 10-15 likely endpoints with HTTP methods.
        Return as JSON: {{"endpoints": [{{"url": "/api/users", "method": "GET", "description": "Get users"}}]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="code_engine", prompt=prompt, max_tokens=500
            )

            if result.get("output"):
                try:
                    ai_endpoints = json.loads(result["output"])

                    for endpoint_data in ai_endpoints.get("endpoints", []):
                        endpoint = APIEndpoint(
                            url=endpoint_data.get("url", ""),
                            method=endpoint_data.get("method", "GET"),
                            parameters=[],
                            auth_required=True,  # Assume auth required for AI predictions
                            api_type="REST",
                            description=endpoint_data.get(
                                "description", "AI predicted"
                            ),
                            source="ai_discovery",
                        )

                        # Avoid duplicates
                        if not any(
                            e.url == endpoint.url and e.method == endpoint.method
                            for e in self.api_endpoints
                        ):
                            self.api_endpoints.append(endpoint)

                except json.JSONDecodeError:
                    logger.warning("AI API discovery response not valid JSON")

        except Exception as e:
            logger.error(f"AI API discovery failed: {e}")

    async def _detect_authentication_mechanisms(
        self, recon_results: Dict[str, Any]
    ) -> None:
        """Detect authentication mechanisms"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Detecting authentication mechanisms...",
            phase="auth_detection",
        )

        # Analyze HTTP headers for auth indicators
        live_hosts = []
        for subdomain_data in recon_results.get("subdomains", {}).get("results", []):
            subdomain = subdomain_data.get("subdomain", "")
            if subdomain:
                live_hosts.append(subdomain)

        for host in live_hosts[:10]:  # Limit analysis
            try:
                result = await self.tool_runner.run_tool("http_analyze", host)

                if result and result.get("headers"):
                    auth_mechs = self._extract_auth_mechanisms(result["headers"], host)
                    self.auth_mechanisms.extend(auth_mechs)

            except Exception as e:
                logger.debug(f"Auth detection failed for {host}: {e}")

        # AI-enhanced auth detection
        await self._ai_auth_detection()

    def _extract_auth_mechanisms(
        self, headers: Dict[str, str], host: str
    ) -> List[AuthenticationMechanism]:
        """Extract authentication mechanisms from headers"""
        mechanisms = []

        # Look for auth-related headers
        auth_headers = {
            "authorization": "Bearer/Basic",
            "x-auth-token": "Token",
            "x-api-key": "API Key",
            "set-cookie": "Session",
            "www-authenticate": "Basic/Digest",
        }

        for header, value in headers.items():
            header_lower = header.lower()

            if header_lower in auth_headers:
                auth_type = auth_headers[header_lower]

                # Determine specific auth mechanism
                if "bearer" in value.lower():
                    mechanism = "JWT"
                elif "basic" in value.lower():
                    mechanism = "Basic Auth"
                elif "digest" in value.lower():
                    mechanism = "Digest Auth"
                elif "session" in header_lower:
                    mechanism = "Session"
                elif "api" in header_lower:
                    mechanism = "API Key"
                else:
                    mechanism = auth_type

                mechanisms.append(
                    AuthenticationMechanism(
                        type=mechanism,
                        location="Header",
                        confidence=0.8,
                        details={"header": header, "value_pattern": value[:20]},
                    )
                )

        return mechanisms

    async def _ai_auth_detection(self) -> None:
        """Use AI to enhance authentication detection"""
        if not self.auth_mechanisms:
            return

        auth_summary = "\n".join(
            [f"{t.type} ({t.location})" for t in self.auth_mechanisms]
        )

        prompt = f"""
        Analyze the authentication mechanisms for {self.target}:
        
        Detected Auth:
        {auth_summary}
        
        Based on these findings, identify:
        1. Likely authentication flow (OAuth2, JWT, Session-based)
        2. Potential weak points in the auth implementation
        3. Additional auth endpoints that might exist (/login, /oauth, etc.)
        4. Token handling patterns
        
        Return as JSON with keys: auth_flow, weak_points, additional_endpoints, token_patterns
        """

        try:
            result = await self.ai_router.call_model(
                role="deep_analyst", prompt=prompt, max_tokens=600
            )

            if result.get("output"):
                try:
                    auth_analysis = json.loads(result["output"])

                    # Add additional auth mechanisms suggested by AI
                    for endpoint in auth_analysis.get("additional_endpoints", []):
                        if isinstance(endpoint, str):
                            mechanism = AuthenticationMechanism(
                                type="Endpoint",
                                location="URL",
                                confidence=0.5,
                                details={"endpoint": endpoint},
                            )
                            self.auth_mechanisms.append(mechanism)

                except json.JSONDecodeError:
                    logger.warning("AI auth analysis response not valid JSON")

        except Exception as e:
            logger.error(f"AI auth detection failed: {e}")

    async def _map_interesting_endpoints(self, recon_results: Dict[str, Any]) -> None:
        """Map interesting endpoints based on patterns"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Mapping interesting endpoints...",
            phase="interesting_mapping",
        )

        # Get base URLs from discovered subdomains
        base_urls = []
        for subdomain_data in recon_results.get("subdomains", {}).get("results", []):
            subdomain = subdomain_data.get("subdomain", "")
            if subdomain:
                base_urls.append(f"https://{subdomain}")

        # Check each interesting pattern
        for category, patterns in self.interesting_patterns.items():
            for base_url in base_urls[:10]:  # Limit to prevent excessive requests
                for pattern in patterns:
                    try:
                        url = f"{base_url}{pattern}"

                        # Check if endpoint is accessible
                        result = await self.tool_runner.run_tool("http_probe", url)

                        if result and result.get("accessible"):
                            # Determine risk level
                            risk_level = self._determine_risk_level(category, pattern)

                            interesting_endpoint = InterestingEndpoint(
                                url=url,
                                category=category,
                                risk_level=risk_level,
                                accessible=True,
                                findings=[],
                            )

                            self.interesting_endpoints.append(interesting_endpoint)

                    except Exception as e:
                        logger.debug(
                            f"Interesting endpoint check failed for {url}: {e}"
                        )

        # AI-enhanced interesting endpoint discovery
        await self._ai_interesting_discovery()

    def _determine_risk_level(self, category: str, pattern: str) -> str:
        """Determine risk level for interesting endpoints"""
        high_risk_categories = {"admin", "config", "env", "debug"}
        medium_risk_categories = {"api", "graphql", "upload", "backup"}

        if category in high_risk_categories:
            return "high"
        elif category in medium_risk_categories:
            return "medium"
        else:
            return "low"

    async def _ai_interesting_discovery(self) -> None:
        """Use AI to discover additional interesting endpoints"""
        prompt = f"""
        For the target {self.target}, predict additional interesting endpoints that might exist.
        
        Consider:
        - Development/debug endpoints: /debug, /phpinfo, /server-info
        - Configuration files: /config.json, /settings.xml, /.env
        - Administrative interfaces: /admin.php, /manager.html, /console
        - Backup/exports: /backup.sql, /dump.php, /export.csv
        - Internal tools: /tools, /utilities, /internal
        
        Generate 10-15 high-value endpoints.
        Return as JSON: {{"endpoints": [{{"url": "/admin.php", "category": "admin", "risk_level": "high"}}]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst", prompt=prompt, max_tokens=400
            )

            if result.get("output"):
                try:
                    ai_endpoints = json.loads(result["output"])

                    for endpoint_data in ai_endpoints.get("endpoints", []):
                        interesting_endpoint = InterestingEndpoint(
                            url=endpoint_data.get("url", ""),
                            category=endpoint_data.get("category", "unknown"),
                            risk_level=endpoint_data.get("risk_level", "medium"),
                            accessible=False,  # AI predictions need validation
                            source="ai_prediction",
                        )

                        self.interesting_endpoints.append(interesting_endpoint)

                except json.JSONDecodeError:
                    logger.warning("AI interesting discovery response not valid JSON")

        except Exception as e:
            logger.error(f"AI interesting discovery failed: {e}")

    async def _correlate_cves(self) -> None:
        """Correlate detected technologies with known CVEs"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Correlating CVEs with detected technologies...",
            phase="cve_correlation",
        )

        # Use existing CVE database
        for tech in self.tech_stack:
            if tech.version:
                try:
                    cves = await self.cve_database.lookup_cves(tech.name, tech.version)
                    self.known_cves[f"{tech.name}:{tech.version}"] = cves

                    # Add CVEs to technology component
                    tech.cves = cves

                except Exception as e:
                    logger.debug(
                        f"CVE lookup failed for {tech.name}:{tech.version}: {e}"
                    )

    def _compile_context_tree(self) -> Dict[str, Any]:
        """Compile the complete context tree"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "timestamp": str(asyncio.get_event_loop().time()),
            "technology_stack": {
                "total_count": len(self.tech_stack),
                "by_category": {
                    category: len(
                        [t for t in self.tech_stack if t.category == category]
                    )
                    for category in set(t.category for t in self.tech_stack)
                },
                "components": [asdict(tech) for tech in self.tech_stack],
                "versioned_count": len([t for t in self.tech_stack if t.version]),
            },
            "api_schema": {
                "total_endpoints": len(self.api_endpoints),
                "by_method": {
                    method: len([e for e in self.api_endpoints if e.method == method])
                    for method in set(e.method for e in self.api_endpoints)
                },
                "by_type": {
                    api_type: len(
                        [e for e in self.api_endpoints if e.api_type == api_type]
                    )
                    for api_type in set(e.api_type for e in self.api_endpoints)
                },
                "endpoints": [asdict(endpoint) for endpoint in self.api_endpoints],
                "auth_required_count": len(
                    [e for e in self.api_endpoints if e.auth_required]
                ),
            },
            "authentication": {
                "mechanisms_count": len(self.auth_mechanisms),
                "by_type": {
                    auth_type: len(
                        [a for a in self.auth_mechanisms if a.type == auth_type]
                    )
                    for auth_type in set(a.type for a in self.auth_mechanisms)
                },
                "mechanisms": [asdict(auth) for auth in self.auth_mechanisms],
            },
            "interesting_endpoints": {
                "total_count": len(self.interesting_endpoints),
                "by_category": {
                    category: len(
                        [
                            e
                            for e in self.interesting_endpoints
                            if e.category == category
                        ]
                    )
                    for category in set(e.category for e in self.interesting_endpoints)
                },
                "by_risk_level": {
                    risk: len(
                        [e for e in self.interesting_endpoints if e.risk_level == risk]
                    )
                    for risk in set(e.risk_level for e in self.interesting_endpoints)
                },
                "endpoints": [
                    asdict(endpoint) for endpoint in self.interesting_endpoints
                ],
                "accessible_count": len(
                    [e for e in self.interesting_endpoints if e.accessible]
                ),
            },
            "vulnerabilities": {
                "total_cves": sum(len(cves) for cves in self.known_cves.values()),
                "by_technology": self.known_cves,
                "high_severity_count": sum(
                    len(
                        [
                            cve
                            for cve in cves
                            if cve.get("severity", "low") in ["high", "critical"]
                        ]
                    )
                    for cves in self.known_cves.values()
                ),
            },
            "summary": {
                "complexity_score": self._calculate_complexity_score(),
                "attack_surface": self._calculate_attack_surface(),
                "priority_targets": self._identify_priority_targets(),
            },
        }

    def _calculate_complexity_score(self) -> float:
        """Calculate technology stack complexity score"""
        category_weights = {
            "backend": 0.3,
            "frontend": 0.2,
            "database": 0.2,
            "cms": 0.1,
            "framework": 0.2,
        }

        score = 0.0
        for category, weight in category_weights.items():
            count = len([t for t in self.tech_stack if t.category == category])
            score += min(count * weight, 1.0)

        return min(score, 1.0)

    def _calculate_attack_surface(self) -> Dict[str, int]:
        """Calculate attack surface metrics"""
        return {
            "api_endpoints": len(self.api_endpoints),
            "interesting_endpoints": len(self.interesting_endpoints),
            "auth_mechanisms": len(self.auth_mechanisms),
            "technologies_with_cves": len([t for t in self.tech_stack if t.cves]),
        }

    def _identify_priority_targets(self) -> List[str]:
        """Identify priority targets for vulnerability testing"""
        priority_targets = []

        # High-risk interesting endpoints
        high_risk_endpoints = [
            e.url
            for e in self.interesting_endpoints
            if e.risk_level in ["high", "critical"] and e.accessible
        ]
        priority_targets.extend(high_risk_endpoints)

        # API endpoints with auth
        auth_apis = [e.url for e in self.api_endpoints if e.auth_required]
        priority_targets.extend(auth_apis[:5])  # Limit to top 5

        return priority_targets[:10]  # Return top 10 priority targets
