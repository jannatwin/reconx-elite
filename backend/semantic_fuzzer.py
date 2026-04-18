"""
Semantic Fuzzer - Phase 8 of Agentic Multi-Model Vulnerability Research Engine
Generates contextual wordlists and payloads using Gemini 3 Flash semantic analysis
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ai_router import AIRouter
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


class ApplicationType(Enum):
    BANKING = "banking"
    ECOMMERCE = "ecommerce"
    HEALTHCARE = "healthcare"
    SOCIAL_MEDIA = "social_media"
    ENTERPRISE = "enterprise"
    EDUCATION = "education"
    GOVERNMENT = "government"
    FINTECH = "fintech"
    GAMING = "gaming"
    UNKNOWN = "unknown"


@dataclass
class ContextualWordlist:
    application_type: ApplicationType
    domain_specific_terms: List[str]
    parameter_names: List[str]
    value_patterns: List[str]
    form_fields: List[str]
    api_endpoints: List[str]
    business_logic_terms: List[str]
    confidence: float


@dataclass
class SemanticPayload:
    payload_type: str
    parameter: str
    value: str
    context: str
    application_relevance: float
    attack_vector: str


class SemanticFuzzer:
    """Semantic fuzzer using Gemini 3 Flash for contextual analysis"""

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
        self.contextual_wordlists: List[ContextualWordlist] = []
        self.semantic_payloads: List[SemanticPayload] = []

        # Application type indicators
        self.application_indicators = {
            ApplicationType.BANKING: {
                "keywords": [
                    "bank",
                    "transaction",
                    "account",
                    "payment",
                    "transfer",
                    "deposit",
                    "withdraw",
                    "balance",
                    "credit",
                    "debit",
                    "loan",
                    "mortgage",
                    "interest",
                    "routing",
                    "swift",
                    "iban",
                    "ach",
                ],
                "endpoints": [
                    "/api/transfer",
                    "/api/payment",
                    "/api/account",
                    "/api/transaction",
                    "/api/balance",
                    "/api/deposit",
                    "/api/withdraw",
                ],
                "forms": [
                    "account_number",
                    "routing_number",
                    "amount",
                    "recipient",
                    "transfer_type",
                    "payment_method",
                ],
                "parameters": [
                    "account_id",
                    "transaction_id",
                    "payment_id",
                    "transfer_id",
                    "balance",
                    "amount",
                    "currency",
                    "recipient_id",
                ],
            },
            ApplicationType.ECOMMERCE: {
                "keywords": [
                    "shop",
                    "cart",
                    "product",
                    "order",
                    "purchase",
                    "checkout",
                    "inventory",
                    "shipping",
                    "billing",
                    "coupon",
                    "discount",
                    "wishlist",
                    "review",
                    "catalog",
                ],
                "endpoints": [
                    "/api/cart",
                    "/api/order",
                    "/api/product",
                    "/api/checkout",
                    "/api/payment",
                    "/api/inventory",
                ],
                "forms": [
                    "product_id",
                    "quantity",
                    "price",
                    "discount_code",
                    "shipping_address",
                    "billing_address",
                    "payment_method",
                ],
                "parameters": [
                    "product_id",
                    "order_id",
                    "cart_id",
                    "item_id",
                    "sku",
                    "quantity",
                    "price",
                    "discount_code",
                    "coupon_code",
                ],
            },
            ApplicationType.HEALTHCARE: {
                "keywords": [
                    "patient",
                    "doctor",
                    "medical",
                    "health",
                    "diagnosis",
                    "treatment",
                    "prescription",
                    "record",
                    "appointment",
                    "hospital",
                    "clinic",
                    "insurance",
                ],
                "endpoints": [
                    "/api/patient",
                    "/api/record",
                    "/api/appointment",
                    "/api/prescription",
                    "/api/diagnosis",
                ],
                "forms": [
                    "patient_id",
                    "medical_record",
                    "diagnosis_code",
                    "prescription_id",
                    "appointment_date",
                    "insurance_number",
                ],
                "parameters": [
                    "patient_id",
                    "record_id",
                    "appointment_id",
                    "prescription_id",
                    "diagnosis_id",
                    "insurance_number",
                    "medical_code",
                ],
            },
            ApplicationType.SOCIAL_MEDIA: {
                "keywords": [
                    "user",
                    "profile",
                    "post",
                    "comment",
                    "like",
                    "share",
                    "follow",
                    "friend",
                    "message",
                    "chat",
                    "group",
                    "community",
                    "timeline",
                ],
                "endpoints": [
                    "/api/user",
                    "/api/profile",
                    "/api/post",
                    "/api/comment",
                    "/api/message",
                    "/api/friend",
                ],
                "forms": [
                    "username",
                    "email",
                    "password",
                    "profile_picture",
                    "bio",
                    "post_content",
                    "comment_text",
                ],
                "parameters": [
                    "user_id",
                    "post_id",
                    "comment_id",
                    "message_id",
                    "group_id",
                    "profile_id",
                    "friend_id",
                ],
            },
            ApplicationType.ENTERPRISE: {
                "keywords": [
                    "employee",
                    "hr",
                    "payroll",
                    "timesheet",
                    "project",
                    "task",
                    "report",
                    "dashboard",
                    "analytics",
                    "workflow",
                    "approval",
                    "document",
                ],
                "endpoints": [
                    "/api/employee",
                    "/api/project",
                    "/api/task",
                    "/api/report",
                    "/api/approval",
                ],
                "forms": [
                    "employee_id",
                    "project_id",
                    "task_id",
                    "report_id",
                    "approval_id",
                    "document_id",
                ],
                "parameters": [
                    "employee_id",
                    "project_id",
                    "task_id",
                    "report_id",
                    "approval_id",
                    "department_id",
                    "manager_id",
                ],
            },
        }

    async def execute(self, context_tree: Dict[str, Any]) -> Dict[str, Any]:
        """Execute semantic fuzzing analysis"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting semantic fuzzing analysis...",
            phase="semantic_fuzzing",
        )

        try:
            # Phase 8.1: Application Type Detection
            await self._detect_application_type(context_tree)

            # Phase 8.2: Endpoint and Form Analysis
            await self._analyze_endpoints_and_forms(context_tree)

            # Phase 8.3: Contextual Wordlist Generation
            await self._generate_contextual_wordlists()

            # Phase 8.4: Semantic Payload Generation
            await self._generate_semantic_payloads()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Semantic fuzzing completed: {len(self.contextual_wordlists)} wordlists, {len(self.semantic_payloads)} payloads",
                phase="semantic_fuzzing",
            )

            return results

        except Exception as e:
            logger.error(f"Semantic fuzzing failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Semantic fuzzing failed: {str(e)}",
                phase="semantic_fuzzing",
            )
            raise

    async def _detect_application_type(self, context_tree: Dict[str, Any]) -> None:
        """Detect application type using semantic analysis"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Detecting application type...",
            phase="semantic_fuzzing",
        )

        # Collect semantic indicators
        indicators = self._collect_semantic_indicators(context_tree)

        # Use AI for application type detection
        app_type = await self._ai_detect_application_type(indicators)

        # Create contextual wordlist for detected type
        await self._create_application_wordlist(app_type, indicators)

    def _collect_semantic_indicators(
        self, context_tree: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Collect semantic indicators from context tree"""
        indicators = {
            "domain": self.target,
            "subdomains": [],
            "endpoints": [],
            "technology_stack": [],
            "interesting_endpoints": [],
            "page_titles": [],
            "form_fields": [],
        }

        # Extract subdomains
        subdomains = context_tree.get("subdomains", {}).get("results", [])
        indicators["subdomains"] = [sub.get("subdomain", "") for sub in subdomains[:20]]

        # Extract endpoints
        api_endpoints = context_tree.get("api_schema", {}).get("endpoints", [])
        indicators["endpoints"] = [ep.get("url", "") for ep in api_endpoints[:30]]

        # Extract technology stack
        tech_stack = context_tree.get("technology_stack", {}).get("components", [])
        indicators["technology_stack"] = [
            tech.get("name", "") for tech in tech_stack[:15]
        ]

        # Extract interesting endpoints
        interesting_endpoints = context_tree.get("interesting_endpoints", {}).get(
            "endpoints", []
        )
        indicators["interesting_endpoints"] = [
            ep.get("url", "") for ep in interesting_endpoints[:20]
        ]

        return indicators

    async def _ai_detect_application_type(
        self, indicators: Dict[str, Any]
    ) -> ApplicationType:
        """Use AI to detect application type"""
        prompt = f"""
        Analyze the following semantic indicators to determine the application type for {self.target}:
        
        Domain: {indicators['domain']}
        Subdomains: {indicators['subdomains'][:10]}
        Endpoints: {indicators['endpoints'][:15]}
        Technology Stack: {indicators['technology_stack'][:10]}
        Interesting Endpoints: {indicators['interesting_endpoints'][:10]}
        
        Application types to consider:
        - banking: Financial services, transactions, accounts
        - ecommerce: Online shopping, products, orders, cart
        - healthcare: Medical records, patients, appointments
        - social_media: Users, profiles, posts, messaging
        - enterprise: Business applications, employees, projects
        - education: Learning, courses, students, teachers
        - government: Public services, administration
        - fintech: Financial technology, modern banking
        - gaming: Games, players, scores, achievements
        
        Return as JSON: {{"application_type": "banking", "confidence": 0.9, "reasoning": "Found banking-related endpoints and terminology"}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",  # Use Gemini 3 Flash for high-speed analysis
                prompt=prompt,
                max_tokens=300,
                task_type="data_parsing",
            )

            if result.get("output"):
                try:
                    analysis = json.loads(result["output"])
                    app_type_str = analysis.get("application_type", "unknown")
                    confidence = analysis.get("confidence", 0.5)

                    # Convert to enum
                    for app_type in ApplicationType:
                        if app_type.value == app_type_str:
                            return app_type

                    return ApplicationType.UNKNOWN

                except json.JSONDecodeError:
                    logger.warning(
                        "AI application type detection response not valid JSON"
                    )

        except Exception as e:
            logger.error(f"AI application type detection failed: {e}")

        return ApplicationType.UNKNOWN

    async def _create_application_wordlist(
        self, app_type: ApplicationType, indicators: Dict[str, Any]
    ) -> None:
        """Create contextual wordlist for detected application type"""
        if app_type == ApplicationType.UNKNOWN:
            return

        # Get base terms for application type
        base_terms = self.application_indicators.get(app_type, {})

        # Extract domain-specific terms from indicators
        domain_terms = self._extract_domain_terms(indicators, app_type)

        # Create contextual wordlist
        wordlist = ContextualWordlist(
            application_type=app_type,
            domain_specific_terms=domain_terms,
            parameter_names=base_terms.get("parameters", []),
            value_patterns=self._generate_value_patterns(app_type),
            form_fields=base_terms.get("forms", []),
            api_endpoints=base_terms.get("endpoints", []),
            business_logic_terms=base_terms.get("keywords", []),
            confidence=0.8,
        )

        self.contextual_wordlists.append(wordlist)

    def _extract_domain_terms(
        self, indicators: Dict[str, Any], app_type: ApplicationType
    ) -> List[str]:
        """Extract domain-specific terms from indicators"""
        terms = []

        # Extract from endpoints
        for endpoint in indicators.get("endpoints", []):
            # Extract meaningful parts from URL paths
            parts = endpoint.split("/")
            for part in parts:
                if part and len(part) > 2 and part not in terms:
                    terms.append(part)

        # Extract from subdomains
        for subdomain in indicators.get("subdomains", []):
            parts = subdomain.split(".")
            for part in parts:
                if part and len(part) > 2 and part not in terms:
                    terms.append(part)

        # Extract from technology stack
        for tech in indicators.get("technology_stack", []):
            if tech and len(tech) > 2 and tech not in terms:
                terms.append(tech)

        # Filter terms based on application relevance
        relevant_terms = []
        app_keywords = self.application_indicators.get(app_type, {}).get("keywords", [])

        for term in terms:
            term_lower = term.lower()
            # Check if term is related to application type
            if any(keyword in term_lower for keyword in app_keywords):
                relevant_terms.append(term)
            elif any(
                keyword in term_lower
                for keyword in ["api", "user", "admin", "data", "config", "service"]
            ):
                relevant_terms.append(term)

        return relevant_terms[:50]  # Limit to prevent token overflow

    def _generate_value_patterns(self, app_type: ApplicationType) -> List[str]:
        """Generate value patterns for application type"""
        patterns = {
            ApplicationType.BANKING: [
                "123456789",
                "987654321",
                "1000000",
                "0.01",
                "999999.99",
                "USD",
                "EUR",
                "GBP",
                "CREDIT",
                "DEBIT",
                "TRANSFER",
                "CHECKING",
                "SAVINGS",
                "LOAN",
                "MORTGAGE",
            ],
            ApplicationType.ECOMMERCE: [
                "999999",
                "1",
                "0",
                "0.01",
                "99.99",
                "FREE",
                "DISCOUNT",
                "SALE",
                "PROMO",
                "COUPON",
                "SHIPPING",
                "TAX",
                "INVENTORY",
                "STOCK",
            ],
            ApplicationType.HEALTHCARE: [
                "123456789",
                "MRN",
                "DOB",
                "ICD10",
                "CPT",
                "PATIENT",
                "DOCTOR",
                "NURSE",
                "HOSPITAL",
                "CLINIC",
                "INSURANCE",
                "PRESCRIPTION",
            ],
            ApplicationType.SOCIAL_MEDIA: [
                "user123",
                "testuser",
                "admin",
                "moderator",
                "public",
                "private",
                "friends",
                "followers",
                "likes",
                "shares",
                "comments",
                "posts",
            ],
            ApplicationType.ENTERPRISE: [
                "EMP001",
                "MGR001",
                "DEPT001",
                "PROJ001",
                "APPROVED",
                "REJECTED",
                "PENDING",
                "REVIEW",
                "QUARTERLY",
                "MONTHLY",
                "WEEKLY",
                "DAILY",
            ],
        }

        return patterns.get(app_type, ["test", "demo", "sample", "example"])

    async def _analyze_endpoints_and_forms(self, context_tree: Dict[str, Any]) -> None:
        """Analyze endpoints and forms for semantic patterns"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Analyzing endpoints and forms...",
            phase="semantic_fuzzing",
        )

        # Get live hosts for form analysis
        live_hosts = self._get_live_hosts(context_tree)

        for host in live_hosts[:10]:  # Limit analysis
            try:
                await self._analyze_host_forms(host)
            except Exception as e:
                logger.debug(f"Form analysis failed for {host}: {e}")

    def _get_live_hosts(self, context_tree: Dict[str, Any]) -> List[str]:
        """Get list of live hosts from context tree"""
        hosts = []

        # Add main target
        hosts.append(f"https://{self.target}")

        # Add subdomains
        subdomains = context_tree.get("subdomains", {}).get("results", [])
        for subdomain_data in subdomains[:20]:
            subdomain = subdomain_data.get("subdomain", "")
            if subdomain:
                hosts.append(f"https://{subdomain}")

        return hosts

    async def _analyze_host_forms(self, host: str) -> None:
        """Analyze HTML forms on a host"""
        try:
            # Fetch page content
            result = await self.tool_runner.run_tool(
                "http_request", {"url": host, "method": "GET"}
            )

            if result and result.get("data"):
                html_content = result.get("data", "")

                # Use AI to analyze forms
                form_analysis = await self._ai_analyze_forms(host, html_content)

                # Update wordlists with form findings
                await self._update_wordlists_with_forms(form_analysis)

        except Exception as e:
            logger.debug(f"Host form analysis failed: {e}")

    async def _ai_analyze_forms(self, host: str, html_content: str) -> Dict[str, Any]:
        """Use AI to analyze HTML forms"""
        # Limit content to prevent token overflow
        content_sample = (
            html_content[:10000] if len(html_content) > 10000 else html_content
        )

        prompt = f"""
        Analyze the HTML forms from {host} and extract semantic information:
        
        HTML Content (sample):
        {content_sample}
        
        Extract and categorize:
        1. Form field names and types
        2. Input validation patterns
        3. Hidden fields and their values
        4. Form submission endpoints
        5. Business logic indicators
        
        Return as JSON: {{"forms": [{"fields": [{"name": "email", "type": "email", "validation": "required"}], "action": "/submit", "method": "POST"}], "business_indicators": ["payment", "user_registration"]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",  # Use Gemini 3 Flash for speed
                prompt=prompt,
                max_tokens=800,
                task_type="data_parsing",
            )

            if result.get("output"):
                try:
                    analysis = json.loads(result["output"])
                    return analysis
                except json.JSONDecodeError:
                    logger.warning("AI form analysis response not valid JSON")

        except Exception as e:
            logger.error(f"AI form analysis failed: {e}")

        return {"forms": [], "business_indicators": []}

    async def _update_wordlists_with_forms(self, form_analysis: Dict[str, Any]) -> None:
        """Update wordlists with form analysis findings"""
        for wordlist in self.contextual_wordlists:
            # Add form fields
            forms = form_analysis.get("forms", [])
            for form in forms:
                fields = form.get("fields", [])
                for field in fields:
                    field_name = field.get("name", "")
                    if field_name and field_name not in wordlist.form_fields:
                        wordlist.form_fields.append(field_name)

            # Add business indicators
            business_indicators = form_analysis.get("business_indicators", [])
            for indicator in business_indicators:
                if indicator and indicator not in wordlist.business_logic_terms:
                    wordlist.business_logic_terms.append(indicator)

    async def _generate_contextual_wordlists(self) -> None:
        """Generate enhanced contextual wordlists using AI"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating enhanced contextual wordlists...",
            phase="semantic_fuzzing",
        )

        for wordlist in self.contextual_wordlists:
            try:
                enhanced_wordlist = await self._ai_enhance_wordlist(wordlist)

                # Update wordlist with AI enhancements
                wordlist.domain_specific_terms.extend(
                    enhanced_wordlist.get("additional_terms", [])
                )
                wordlist.parameter_names.extend(
                    enhanced_wordlist.get("additional_parameters", [])
                )
                wordlist.value_patterns.extend(
                    enhanced_wordlist.get("additional_patterns", [])
                )

                # Remove duplicates
                wordlist.domain_specific_terms = list(
                    set(wordlist.domain_specific_terms)
                )
                wordlist.parameter_names = list(set(wordlist.parameter_names))
                wordlist.value_patterns = list(set(wordlist.value_patterns))

            except Exception as e:
                logger.debug(f"Wordlist enhancement failed: {e}")

    async def _ai_enhance_wordlist(
        self, wordlist: ContextualWordlist
    ) -> Dict[str, Any]:
        """Use AI to enhance wordlist"""
        app_type = wordlist.application_type.value

        prompt = f"""
        Generate additional semantic terms for {app_type} application targeting {self.target}.
        
        Current terms:
        - Domain-specific: {wordlist.domain_specific_terms[:20]}
        - Parameters: {wordlist.parameter_names[:15]}
        - Value patterns: {wordlist.value_patterns[:10]}
        - Form fields: {wordlist.form_fields[:15]}
        
        Generate 20-30 additional terms for each category:
        1. Domain-specific business terms
        2. Parameter names that might exist
        3. Test values and patterns
        4. Form fields that might be present
        
        Focus on realistic, application-specific terminology.
        Return as JSON: {{"additional_terms": ["term1"], "additional_parameters": ["param1"], "additional_patterns": ["pattern1"], "additional_form_fields": ["field1"]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="fast_analyst",
                prompt=prompt,
                max_tokens=600,
                task_type="pattern_recognition",
            )

            if result.get("output"):
                try:
                    enhancement = json.loads(result["output"])
                    return enhancement
                except json.JSONDecodeError:
                    logger.warning("AI wordlist enhancement response not valid JSON")

        except Exception as e:
            logger.error(f"AI wordlist enhancement failed: {e}")

        return {
            "additional_terms": [],
            "additional_parameters": [],
            "additional_patterns": [],
            "additional_form_fields": [],
        }

    async def _generate_semantic_payloads(self) -> None:
        """Generate semantic payloads based on wordlists"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating semantic payloads...",
            phase="semantic_fuzzing",
        )

        for wordlist in self.contextual_wordlists:
            try:
                payloads = await self._generate_wordlist_payloads(wordlist)
                self.semantic_payloads.extend(payloads)
            except Exception as e:
                logger.debug(f"Payload generation failed: {e}")

    async def _generate_wordlist_payloads(
        self, wordlist: ContextualWordlist
    ) -> List[SemanticPayload]:
        """Generate payloads for a specific wordlist"""
        payloads = []

        # Generate parameter-based payloads
        for param in wordlist.parameter_names[:20]:
            for value in wordlist.value_patterns[:10]:
                payload = SemanticPayload(
                    payload_type="parameter_test",
                    parameter=param,
                    value=value,
                    context=f"{wordlist.application_type.value} parameter testing",
                    application_relevance=0.8,
                    attack_vector="parameter_manipulation",
                )
                payloads.append(payload)

        # Generate business logic payloads
        for term in wordlist.business_logic_terms[:15]:
            payload = SemanticPayload(
                payload_type="business_logic",
                parameter="test_parameter",
                value=term,
                context=f"{wordlist.application_type.value} business logic testing",
                application_relevance=0.9,
                attack_vector="business_logic_manipulation",
            )
            payloads.append(payload)

        return payloads[:100]  # Limit payloads per wordlist

    def _compile_results(self) -> Dict[str, Any]:
        """Compile semantic fuzzing results"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "module": "semantic_fuzzer",
            "contextual_wordlists": {
                "total_count": len(self.contextual_wordlists),
                "application_types": [
                    wl.application_type.value for wl in self.contextual_wordlists
                ],
                "results": [asdict(wordlist) for wordlist in self.contextual_wordlists],
                "total_terms": sum(
                    len(wl.domain_specific_terms) for wl in self.contextual_wordlists
                ),
                "total_parameters": sum(
                    len(wl.parameter_names) for wl in self.contextual_wordlists
                ),
            },
            "semantic_payloads": {
                "total_count": len(self.semantic_payloads),
                "payload_types": list(
                    set(p.payload_type for p in self.semantic_payloads)
                ),
                "attack_vectors": list(
                    set(p.attack_vector for p in self.semantic_payloads)
                ),
                "results": [
                    asdict(payload) for payload in self.semantic_payloads[:50]
                ],  # Limit for response size
                "high_relevance_count": len(
                    [
                        p
                        for p in self.semantic_payloads
                        if p.application_relevance >= 0.8
                    ]
                ),
            },
            "summary": {
                "wordlists_generated": len(self.contextual_wordlists),
                "payloads_generated": len(self.semantic_payloads),
                "application_types_detected": list(
                    set(wl.application_type.value for wl in self.contextual_wordlists)
                ),
                "average_confidence": sum(
                    wl.confidence for wl in self.contextual_wordlists
                )
                / max(len(self.contextual_wordlists), 1),
                "recommendation": "Use semantic payloads for targeted vulnerability testing based on application context",
            },
        }
