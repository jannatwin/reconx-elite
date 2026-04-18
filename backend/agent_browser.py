"""
Agentic Browser - Phase 8 of Agentic Multi-Model Vulnerability Research Engine
Playwright integration for SPA handling and complex authentication flows
"""

import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ai_router import AIRouter
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Playwright not available. Install with: pip install playwright")

logger = logging.getLogger(__name__)


class AuthenticationType(Enum):
    BASIC_AUTH = "basic_auth"
    FORM_LOGIN = "form_login"
    OAUTH = "oauth"
    SAML = "saml"
    MFA = "mfa"
    JWT_TOKEN = "jwt_token"
    SESSION_COOKIE = "session_cookie"
    API_KEY = "api_key"
    UNKNOWN = "unknown"


@dataclass
class BrowserSession:
    session_id: str
    authentication_type: AuthenticationType
    cookies: List[Dict[str, Any]]
    local_storage: Dict[str, Any]
    session_storage: Dict[str, Any]
    access_tokens: Dict[str, str]
    headers: Dict[str, str]
    user_agent: str
    is_authenticated: bool
    confidence: float


@dataclass
class RouteDiscovery:
    route_path: str
    route_method: str
    requires_auth: bool
    parameters: List[str]
    discovered_from: str


class AgenticBrowser:
    """Agentic browser using Playwright for SPA and complex auth flows"""

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

        # Storage for results
        self.browser_session: Optional[BrowserSession] = None
        self.discovered_routes: List[RouteDiscovery] = []
        self.form_analysis: Dict[str, Any] = {}

        # Playwright instances
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

        # Authentication patterns
        self.auth_patterns = {
            AuthenticationType.BASIC_AUTH: {
                "indicators": ["www-authenticate", "basic realm"],
                "selectors": [],
            },
            AuthenticationType.FORM_LOGIN: {
                "indicators": ["login", "signin", "auth", "password"],
                "selectors": [
                    'input[type="password"]',
                    'form[action*="login"]',
                    'form[action*="auth"]',
                ],
            },
            AuthenticationType.OAUTH: {
                "indicators": ["oauth", "authorize", "client_id", "redirect_uri"],
                "selectors": ['a[href*="oauth"]', "button[data-oauth]"],
            },
            AuthenticationType.SAML: {
                "indicators": ["saml", "sso", "identity provider"],
                "selectors": ['form[action*="saml"]', 'input[name="SAMLRequest"]'],
            },
            AuthenticationType.MFA: {
                "indicators": ["mfa", "2fa", "totp", "verification code"],
                "selectors": ['input[placeholder*="code"]', 'input[name*="mfa"]'],
            },
            AuthenticationType.JWT_TOKEN: {
                "indicators": ["jwt", "token", "bearer"],
                "selectors": ['script[src*="jwt"]', 'meta[name*="token"]'],
            },
        }

        # Common login credentials for testing
        self.test_credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "test", "password": "test"},
            {"username": "user", "password": "password"},
            {"username": "demo", "password": "demo"},
            {"username": "guest", "password": "guest"},
        ]

    async def execute(self, credentials: Dict[str, str] = None) -> Dict[str, Any]:
        """Execute agentic browser automation"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting agentic browser automation...",
            phase="agent_browser",
        )

        if not PLAYWRIGHT_AVAILABLE:
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                "Playwright not available. Install with: pip install playwright",
                phase="agent_browser",
            )
            return {"error": "Playwright not available"}

        try:
            # Phase 8.1: Initialize Browser
            await self._initialize_browser()

            # Phase 8.2: Authentication Analysis
            await self._analyze_authentication()

            # Phase 8.3: Handle Authentication
            await self._handle_authentication(credentials)

            # Phase 8.4: SPA Route Discovery
            await self._discover_spa_routes()

            # Phase 8.5: Form Analysis
            await self._analyze_forms()

            # Phase 8.6: Extract Session Data
            await self._extract_session_data()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Browser automation completed: {len(self.discovered_routes)} routes discovered, "
                f"authenticated: {self.browser_session.is_authenticated if self.browser_session else False}",
                phase="agent_browser",
            )

            return results

        except Exception as e:
            logger.error(f"Agentic browser execution failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Browser automation failed: {str(e)}",
                phase="agent_browser",
            )
            raise
        finally:
            await self._cleanup_browser()

    async def _initialize_browser(self) -> None:
        """Initialize Playwright browser"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Initializing browser...", phase="agent_browser"
        )

        self.playwright = await async_playwright().start()

        # Launch browser with stealth options
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-web-security",
                "--disable-features=VizDisplayCompositor",
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ],
        )

        # Create context with stealth settings
        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True,
        )

        # Create page
        self.page = await self.context.new_page()

        # Set up request/response interception
        await self.page.route("**/*", self._handle_request)

    async def _handle_request(self, route) -> None:
        """Handle requests for route discovery"""
        request = route.request

        # Log API requests
        if "/api/" in request.url:
            route_info = RouteDiscovery(
                route_path=request.url,
                route_method=request.method,
                requires_auth=True,  # Assume API routes require auth
                parameters=(
                    list(request.post_data_json.keys())
                    if request.post_data_json
                    else []
                ),
                discovered_from="request_interception",
            )

            # Avoid duplicates
            if not any(
                r.route_path == route_info.route_path
                and r.route_method == route_info.route_method
                for r in self.discovered_routes
            ):
                self.discovered_routes.append(route_info)

        await route.continue_()

    async def _analyze_authentication(self) -> None:
        """Analyze authentication type and requirements"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Analyzing authentication...",
            phase="agent_browser",
        )

        # Navigate to target
        url = f"https://{self.target}"
        await self.page.goto(url, wait_until="networkidle")

        # Get page content for analysis
        content = await self.page.content()
        title = await self.page.title()

        # Use AI to analyze authentication
        auth_type = await self._ai_analyze_authentication(content, title)

        # Create initial browser session
        self.browser_session = BrowserSession(
            session_id=self.session_id,
            authentication_type=auth_type,
            cookies=[],
            local_storage={},
            session_storage={},
            access_tokens={},
            headers={},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            is_authenticated=False,
            confidence=0.5,
        )

    async def _ai_analyze_authentication(
        self, content: str, title: str
    ) -> AuthenticationType:
        """Use AI to analyze authentication type"""
        # Limit content to prevent token overflow
        content_sample = content[:5000] if len(content) > 5000 else content

        prompt = f"""
        Analyze the authentication requirements for {self.target}:
        
        Title: {title}
        HTML Content (sample):
        {content_sample}
        
        Authentication types to consider:
        - basic_auth: HTTP Basic Authentication
        - form_login: Traditional username/password form
        - oauth: OAuth 2.0 flow
        - saml: SAML SSO
        - mfa: Multi-factor authentication
        - jwt_token: JWT token-based auth
        - session_cookie: Session cookie authentication
        - api_key: API key authentication
        - unknown: Unknown or no authentication
        
        Look for:
        1. Login forms and their structure
        2. Authentication-related JavaScript
        3. OAuth/SAML indicators
        4. API endpoints and their auth requirements
        5. Session management patterns
        
        Return as JSON: {{"auth_type": "form_login", "confidence": 0.9, "indicators": ["login_form", "password_field"]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",  # Use Gemini 3 Flash for speed
                prompt=prompt,
                max_tokens=400,
                task_type="data_parsing",
            )

            if result.get("output"):
                try:
                    analysis = json.loads(result["output"])
                    auth_type_str = analysis.get("auth_type", "unknown")
                    confidence = analysis.get("confidence", 0.5)

                    # Convert to enum
                    for auth_type in AuthenticationType:
                        if auth_type.value == auth_type_str:
                            return auth_type

                    return AuthenticationType.UNKNOWN

                except json.JSONDecodeError:
                    logger.warning("AI authentication analysis response not valid JSON")

        except Exception as e:
            logger.error(f"AI authentication analysis failed: {e}")

        return AuthenticationType.UNKNOWN

    async def _handle_authentication(self, credentials: Dict[str, str] = None) -> None:
        """Handle authentication flow"""
        if not self.browser_session:
            return

        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Handling {self.browser_session.authentication_type.value} authentication...",
            phase="agent_browser",
        )

        auth_handlers = {
            AuthenticationType.BASIC_AUTH: self._handle_basic_auth,
            AuthenticationType.FORM_LOGIN: self._handle_form_login,
            AuthenticationType.OAUTH: self._handle_oauth,
            AuthenticationType.SAML: self._handle_saml,
            AuthenticationType.JWT_TOKEN: self._handle_jwt_token,
            AuthenticationType.SESSION_COOKIE: self._handle_session_cookie,
        }

        handler = auth_handlers.get(self.browser_session.authentication_type)
        if handler:
            await handler(credentials)
        else:
            await self.ws_manager.send_log(
                self.session_id,
                "warning",
                f"No handler for authentication type: {self.browser_session.authentication_type.value}",
                phase="agent_browser",
            )

    async def _handle_basic_auth(self, credentials: Dict[str, str] = None) -> None:
        """Handle HTTP Basic Authentication"""
        if not credentials:
            credentials = self.test_credentials[0]

        username = credentials.get("username", "admin")
        password = credentials.get("password", "admin")

        # Create new context with basic auth
        self.context = await self.browser.new_context(
            http_credentials={"username": username, "password": password},
            ignore_https_errors=True,
        )

        self.page = await self.context.new_page()

        # Test authentication
        url = f"https://{self.target}"
        response = await self.page.goto(url, wait_until="networkidle")

        if response and response.status != 401:
            self.browser_session.is_authenticated = True
            self.browser_session.confidence = 0.8
            self.browser_session.access_tokens["basic_auth"] = f"{username}:{password}"

    async def _handle_form_login(self, credentials: Dict[str, str] = None) -> None:
        """Handle form-based login"""
        if not credentials:
            # Try test credentials
            for test_creds in self.test_credentials:
                success = await self._try_form_login(test_creds)
                if success:
                    break
        else:
            await self._try_form_login(credentials)

    async def _try_form_login(self, credentials: Dict[str, str]) -> bool:
        """Try form login with specific credentials"""
        try:
            # Look for login form
            login_forms = await self.page.query_selector_all("form")

            for form in login_forms:
                # Check if form looks like a login form
                form_action = await form.get_attribute("action") or ""
                form_method = await form.get_attribute("method") or "POST"

                if any(
                    indicator in form_action.lower()
                    for indicator in ["login", "auth", "signin"]
                ):
                    # Find username and password fields
                    username_field = await form.query_selector(
                        'input[type="email"], input[type="text"], input[name*="user"], input[name*="email"], input[id*="user"]'
                    )
                    password_field = await form.query_selector('input[type="password"]')

                    if username_field and password_field:
                        # Fill credentials
                        await username_field.fill(credentials.get("username", ""))
                        await password_field.fill(credentials.get("password", ""))

                        # Submit form
                        await form.click()
                        await self.page.wait_for_load_state("networkidle")

                        # Check if login was successful
                        current_url = self.page.url
                        if (
                            "login" not in current_url.lower()
                            and "auth" not in current_url.lower()
                        ):
                            self.browser_session.is_authenticated = True
                            self.browser_session.confidence = 0.9
                            return True

            return False

        except Exception as e:
            logger.debug(f"Form login attempt failed: {e}")
            return False

    async def _handle_oauth(self, credentials: Dict[str, str] = None) -> None:
        """Handle OAuth authentication"""
        # Look for OAuth buttons/links
        oauth_links = await self.page.query_selector_all(
            'a[href*="oauth"], button[data-oauth]'
        )

        for link in oauth_links:
            try:
                await link.click()
                await self.page.wait_for_load_state("networkidle")

                # Check if redirected back with tokens
                current_url = self.page.url
                if "access_token" in current_url or "code=" in current_url:
                    self.browser_session.is_authenticated = True
                    self.browser_session.confidence = 0.7
                    break

            except Exception as e:
                logger.debug(f"OAuth attempt failed: {e}")

    async def _handle_saml(self, credentials: Dict[str, str] = None) -> None:
        """Handle SAML authentication"""
        # Look for SAML forms
        saml_forms = await self.page.query_selector_all('form[action*="saml"]')

        for form in saml_forms:
            try:
                await form.click()
                await self.page.wait_for_load_state("networkidle")

                # Check if authenticated
                current_url = self.page.url
                if "saml" not in current_url.lower():
                    self.browser_session.is_authenticated = True
                    self.browser_session.confidence = 0.7
                    break

            except Exception as e:
                logger.debug(f"SAML attempt failed: {e}")

    async def _handle_jwt_token(self, credentials: Dict[str, str] = None) -> None:
        """Handle JWT token authentication"""
        # Look for JWT tokens in page
        page_content = await self.page.content()

        # Simple JWT pattern matching
        import re

        jwt_pattern = r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
        jwt_matches = re.findall(jwt_pattern, page_content)

        if jwt_matches:
            self.browser_session.access_tokens["jwt"] = jwt_matches[0]
            self.browser_session.is_authenticated = True
            self.browser_session.confidence = 0.6

    async def _handle_session_cookie(self, credentials: Dict[str, str] = None) -> None:
        """Handle session cookie authentication"""
        # Cookies will be extracted in _extract_session_data
        pass

    async def _discover_spa_routes(self) -> None:
        """Discover SPA routes by analyzing JavaScript and navigation"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Discovering SPA routes...", phase="agent_browser"
        )

        try:
            # Get all JavaScript files
            scripts = await self.page.query_selector_all("script[src]")

            for script in scripts:
                src = await script.get_attribute("src")
                if src and ".js" in src:
                    # Analyze JavaScript for routes
                    await self._analyze_js_for_routes(src)

            # Look for client-side routing patterns
            page_content = await self.page.content()
            await self._analyze_content_for_routes(page_content)

            # Try common SPA routes
            await self._probe_common_routes()

        except Exception as e:
            logger.debug(f"SPA route discovery failed: {e}")

    async def _analyze_js_for_routes(self, script_src: str) -> None:
        """Analyze JavaScript file for route definitions"""
        try:
            # Get script content
            response = await self.page.goto(script_src)
            if response and response.status == 200:
                js_content = await response.text()

                # Look for route patterns
                route_patterns = [
                    r'path:\s*[\'"]([^\'"]+)[\'"]',
                    r'route:\s*[\'"]([^\'"]+)[\'"]',
                    r'/api/([^\'"\s]+)',
                    r'router\.get\([\'"]([^\'"]+)[\'"]',
                    r'app\.get\([\'"]([^\'"]+)[\'"]',
                ]

                for pattern in route_patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        route = RouteDiscovery(
                            route_path=(
                                f"/{match}" if not match.startswith("/") else match
                            ),
                            route_method="GET",
                            requires_auth=True,
                            parameters=[],
                            discovered_from="javascript_analysis",
                        )

                        # Avoid duplicates
                        if not any(
                            r.route_path == route.route_path
                            for r in self.discovered_routes
                        ):
                            self.discovered_routes.append(route)

        except Exception as e:
            logger.debug(f"JS route analysis failed: {e}")

    async def _analyze_content_for_routes(self, content: str) -> None:
        """Analyze page content for route indicators"""
        # Look for navigation links
        link_pattern = r'href=[\'"](/[^\'"]+)[\'"]'
        matches = re.findall(link_pattern, content)

        for match in matches:
            if len(match) > 1 and not match.endswith(
                (".css", ".js", ".png", ".jpg", ".ico")
            ):
                route = RouteDiscovery(
                    route_path=match,
                    route_method="GET",
                    requires_auth=False,
                    parameters=[],
                    discovered_from="content_analysis",
                )

                # Avoid duplicates
                if not any(
                    r.route_path == route.route_path for r in self.discovered_routes
                ):
                    self.discovered_routes.append(route)

    async def _probe_common_routes(self) -> None:
        """Probe common SPA routes"""
        common_routes = [
            "/api/user/profile",
            "/api/user/settings",
            "/api/admin/users",
            "/api/dashboard",
            "/api/data",
            "/config",
            "/admin",
            "/dashboard",
            "/profile",
            "/settings",
        ]

        for route in common_routes:
            try:
                url = f"https://{self.target}{route}"
                response = await self.page.goto(url, wait_until="networkidle")

                if response and response.status == 200:
                    discovered_route = RouteDiscovery(
                        route_path=route,
                        route_method="GET",
                        requires_auth=True,
                        parameters=[],
                        discovered_from="probing",
                    )

                    # Avoid duplicates
                    if not any(r.route_path == route for r in self.discovered_routes):
                        self.discovered_routes.append(discovered_route)

            except Exception as e:
                logger.debug(f"Route probing failed for {route}: {e}")

    async def _analyze_forms(self) -> None:
        """Analyze forms on the page"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Analyzing forms...", phase="agent_browser"
        )

        try:
            forms = await self.page.query_selector_all("form")

            for i, form in enumerate(forms):
                form_info = await self._extract_form_info(form, i)
                self.form_analysis[f"form_{i}"] = form_info

        except Exception as e:
            logger.debug(f"Form analysis failed: {e}")

    async def _extract_form_info(self, form, index: int) -> Dict[str, Any]:
        """Extract information from a form"""
        try:
            action = await form.get_attribute("action") or ""
            method = await form.get_attribute("method") or "POST"

            # Get form fields
            fields = []
            inputs = await form.query_selector_all("input, select, textarea")

            for input_elem in inputs:
                field_info = await self._extract_field_info(input_elem)
                fields.append(field_info)

            return {
                "action": action,
                "method": method,
                "fields": fields,
                "requires_auth": any(
                    field.get("name", "") in ["password", "login", "auth"]
                    for field in fields
                ),
            }

        except Exception as e:
            logger.debug(f"Form info extraction failed: {e}")
            return {}

    async def _extract_field_info(self, field) -> Dict[str, Any]:
        """Extract field information"""
        try:
            field_type = await field.get_attribute("type") or "text"
            field_name = await field.get_attribute("name") or ""
            field_id = await field.get_attribute("id") or ""
            placeholder = await field.get_attribute("placeholder") or ""

            return {
                "type": field_type,
                "name": field_name,
                "id": field_id,
                "placeholder": placeholder,
            }

        except Exception as e:
            logger.debug(f"Field info extraction failed: {e}")
            return {}

    async def _extract_session_data(self) -> None:
        """Extract session data from browser"""
        if not self.browser_session:
            return

        await self.ws_manager.send_log(
            self.session_id, "info", "Extracting session data...", phase="agent_browser"
        )

        try:
            # Extract cookies
            cookies = await self.context.cookies()
            self.browser_session.cookies = cookies

            # Extract local storage
            local_storage = await self.page.evaluate(
                "() => Object.keys(localStorage).reduce((obj, key) => { obj[key] = localStorage[key]; return obj; }, {})"
            )
            self.browser_session.local_storage = local_storage

            # Extract session storage
            session_storage = await self.page.evaluate(
                "() => Object.keys(sessionStorage).reduce((obj, key) => { obj[key] = sessionStorage[key]; return obj; }, {})"
            )
            self.browser_session.session_storage = session_storage

            # Extract authorization headers from storage
            auth_token = (
                local_storage.get("token")
                or local_storage.get("authToken")
                or session_storage.get("token")
            )
            if auth_token:
                self.browser_session.headers["Authorization"] = f"Bearer {auth_token}"
                self.browser_session.access_tokens["bearer"] = auth_token

            # Update confidence based on session data
            if self.browser_session.cookies or self.browser_session.access_tokens:
                self.browser_session.confidence = min(
                    self.browser_session.confidence + 0.2, 1.0
                )

        except Exception as e:
            logger.debug(f"Session data extraction failed: {e}")

    async def _cleanup_browser(self) -> None:
        """Clean up browser resources"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            logger.debug(f"Browser cleanup failed: {e}")

    def _compile_results(self) -> Dict[str, Any]:
        """Compile browser automation results"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "module": "agent_browser",
            "browser_session": {
                "authentication_type": (
                    self.browser_session.authentication_type.value
                    if self.browser_session
                    else "unknown"
                ),
                "is_authenticated": (
                    self.browser_session.is_authenticated
                    if self.browser_session
                    else False
                ),
                "confidence": (
                    self.browser_session.confidence if self.browser_session else 0.0
                ),
                "cookies_count": (
                    len(self.browser_session.cookies) if self.browser_session else 0
                ),
                "access_tokens": (
                    list(self.browser_session.access_tokens.keys())
                    if self.browser_session
                    else []
                ),
                "headers": self.browser_session.headers if self.browser_session else {},
            },
            "discovered_routes": {
                "total_count": len(self.discovered_routes),
                "auth_required_count": len(
                    [r for r in self.discovered_routes if r.requires_auth]
                ),
                "results": [asdict(route) for route in self.discovered_routes],
                "discovery_methods": list(
                    set(r.discovered_from for r in self.discovered_routes)
                ),
            },
            "form_analysis": {
                "total_forms": len(self.form_analysis),
                "auth_forms_count": len(
                    [
                        f
                        for f in self.form_analysis.values()
                        if f.get("requires_auth", False)
                    ]
                ),
                "results": self.form_analysis,
            },
            "summary": {
                "authentication_successful": (
                    self.browser_session.is_authenticated
                    if self.browser_session
                    else False
                ),
                "routes_discovered": len(self.discovered_routes),
                "forms_analyzed": len(self.form_analysis),
                "session_data_extracted": bool(
                    self.browser_session.cookies if self.browser_session else []
                ),
                "recommendation": "Use extracted session data for authenticated vulnerability scanning",
            },
        }
