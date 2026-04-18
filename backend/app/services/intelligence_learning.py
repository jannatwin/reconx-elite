"""Intelligence Learning System for learning from previous findings."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.learning_models import (
    LearningPattern,
    SuccessfulPayload,
    HighValueEndpoint,
)
from app.models.vulnerability import Vulnerability
from app.models.exploit_validation import ExploitValidation

logger = logging.getLogger(__name__)


class IntelligenceLearningService:
    """Advanced learning system for vulnerability discovery optimization."""

    def __init__(self):
        self.pattern_extractors = {
            "endpoint": self._extract_endpoint_patterns,
            "payload": self._extract_payload_patterns,
            "subdomain": self._extract_subdomain_patterns,
            "parameter": self._extract_parameter_patterns,
        }

    def learn_from_vulnerability(
        self,
        db: Session,
        user_id: int,
        vulnerability: Vulnerability,
        validation: Optional[ExploitValidation] = None,
    ) -> Dict[str, Any]:
        """Learn from a discovered vulnerability."""

        learning_results = {
            "patterns_learned": 0,
            "payloads_updated": 0,
            "endpoints_updated": 0,
        }

        try:
            # Extract and store patterns
            patterns = self._extract_patterns_from_vulnerability(vulnerability)
            for pattern_type, pattern_data in patterns.items():
                self._store_learning_pattern(
                    db, user_id, pattern_type, pattern_data, vulnerability
                )
                learning_results["patterns_learned"] += 1

            # Update successful payloads if validation exists
            if validation and validation.validation_status == "confirmed":
                self._update_successful_payloads(db, user_id, vulnerability, validation)
                learning_results["payloads_updated"] += 1

            # Update high-value endpoints
            self._update_high_value_endpoints(db, user_id, vulnerability, validation)
            learning_results["endpoints_updated"] += 1

            logger.info(f"Learning completed for vulnerability {vulnerability.id}")

        except Exception as e:
            logger.error(f"Learning failed for vulnerability {vulnerability.id}: {e}")

        return learning_results

    def _extract_patterns_from_vulnerability(
        self, vulnerability: Vulnerability
    ) -> Dict[str, Dict]:
        """Extract various patterns from vulnerability data."""
        patterns = {}

        # Extract endpoint patterns
        if vulnerability.matched_url:
            patterns["endpoint"] = self._extract_endpoint_patterns(
                vulnerability.matched_url
            )

        # Extract payload patterns from evidence
        if vulnerability.evidence_json:
            patterns["payload"] = self._extract_payload_patterns(
                vulnerability.evidence_json
            )

        # Extract parameter patterns
        if vulnerability.matched_url:
            patterns["parameter"] = self._extract_parameter_patterns(
                vulnerability.matched_url
            )

        return patterns

    def _extract_endpoint_patterns(self, url: str) -> Dict[str, Any]:
        """Extract endpoint patterns from URL."""
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query

        patterns = {
            "path_pattern": self._generalize_path(path),
            "query_patterns": self._extract_query_patterns(query),
            "file_extensions": self._extract_file_extensions(path),
            "path_segments": self._extract_path_segments(path),
        }

        return patterns

    def _generalize_path(self, path: str) -> str:
        """Generalize path pattern by replacing specific values with placeholders."""
        # Replace IDs with placeholders
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)

        # Replace UUIDs with placeholders
        path = re.sub(
            r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?=/|$)",
            "/{uuid}",
            path,
        )

        # Replace common parameters
        path = re.sub(r"/[a-f0-9]{32,}(?=/|$)", "/{hash}", path)
        path = re.sub(r"/[A-Za-z0-9+/]{20,}={0,2}(?=/|$)", "/{base64}", path)

        return path

    def _extract_query_patterns(self, query: str) -> List[str]:
        """Extract parameter patterns from query string."""
        if not query:
            return []

        patterns = []
        params = query.split("&")

        for param in params:
            if "=" in param:
                key = param.split("=")[0]
                patterns.append(key)

        return patterns

    def _extract_file_extensions(self, path: str) -> List[str]:
        """Extract file extensions from path."""
        extensions = []

        # Look for file extensions
        matches = re.findall(r"\.([a-zA-Z0-9]{2,5})(?=/|$)", path)
        extensions.extend(matches)

        return list(set(extensions))

    def _extract_path_segments(self, path: str) -> List[str]:
        """Extract meaningful path segments."""
        segments = []

        parts = path.split("/")
        for part in parts:
            if part and len(part) > 2:  # Skip empty and very short segments
                # Skip obvious IDs and hashes
                if not re.match(r"^[a-f0-9]{8,}$", part) and not re.match(
                    r"^\d+$", part
                ):
                    segments.append(part)

        return segments

    def _extract_payload_patterns(self, evidence: Dict) -> Dict[str, Any]:
        """Extract payload patterns from vulnerability evidence."""
        patterns = {
            "payload_types": [],
            "injection_points": [],
            "encoding_methods": [],
        }

        # Look for payload in evidence
        evidence_str = json.dumps(evidence).lower()

        # Detect payload types
        if "script" in evidence_str or "alert" in evidence_str:
            patterns["payload_types"].append("xss")
        if "union" in evidence_str or "or" in evidence_str:
            patterns["payload_types"].append("sqli")
        if "127.0.0.1" in evidence_str or "localhost" in evidence_str:
            patterns["payload_types"].append("ssrf")

        return patterns

    def _extract_parameter_patterns(self, url: str) -> Dict[str, Any]:
        """Extract parameter patterns from URL."""
        parsed = urlparse(url)
        query = parsed.query

        patterns = {
            "vulnerable_parameters": [],
            "parameter_types": {},
        }

        if query:
            params = query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    patterns["vulnerable_parameters"].append(key)

                    # Classify parameter type
                    param_type = self._classify_parameter(key, value)
                    patterns["parameter_types"][key] = param_type

        return patterns

    def _extract_subdomain_patterns(self, host_or_url: str) -> Dict[str, Any]:
        """Extract lightweight subdomain structure patterns."""
        candidate = host_or_url or ""
        parsed = urlparse(candidate)
        host = parsed.netloc or candidate
        host = host.split(":")[0].strip(".").lower()
        labels = [label for label in host.split(".") if label]

        subdomain_labels = labels[:-2] if len(labels) > 2 else []
        root_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host

        return {
            "root_domain": root_domain,
            "subdomain_depth": len(subdomain_labels),
            "subdomain_labels": subdomain_labels,
            "has_common_env_prefix": bool(
                subdomain_labels
                and subdomain_labels[0]
                in {"dev", "staging", "test", "qa", "api", "admin"}
            ),
        }

    def _classify_parameter(self, key: str, value: str) -> str:
        """Classify parameter type based on name and value."""
        key_lower = key.lower()

        # ID parameters
        if any(id_word in key_lower for id_word in ["id", "uid", "user", "item"]):
            return "identifier"

        # Search parameters
        if any(
            search_word in key_lower for search_word in ["search", "query", "q", "find"]
        ):
            return "search"

        # File parameters
        if any(
            file_word in key_lower for file_word in ["file", "upload", "doc", "image"]
        ):
            return "file"

        # Redirect parameters
        if any(
            redirect_word in key_lower
            for redirect_word in ["redirect", "url", "return", "next"]
        ):
            return "redirect"

        # API parameters
        if any(api_word in key_lower for api_word in ["api", "key", "token", "secret"]):
            return "api"

        return "general"

    def _store_learning_pattern(
        self,
        db: Session,
        user_id: int,
        pattern_type: str,
        pattern_data: Dict,
        vulnerability: Vulnerability,
    ):
        """Store a learning pattern in the database."""

        # Determine vulnerability type
        vuln_type = self._classify_vulnerability_type(vulnerability)

        # Store different pattern types
        if pattern_type == "endpoint":
            self._store_endpoint_pattern(
                db, user_id, pattern_data, vulnerability, vuln_type
            )
        elif pattern_type == "payload":
            self._store_payload_pattern(
                db, user_id, pattern_data, vulnerability, vuln_type
            )
        elif pattern_type == "parameter":
            self._store_parameter_pattern(
                db, user_id, pattern_data, vulnerability, vuln_type
            )

    def _store_endpoint_pattern(
        self,
        db: Session,
        user_id: int,
        pattern_data: Dict,
        vulnerability: Vulnerability,
        vuln_type: str,
    ):
        """Store endpoint learning pattern."""
        path_pattern = pattern_data.get("path_pattern", "")
        if not path_pattern:
            return

        # Check if pattern already exists
        existing = (
            db.query(LearningPattern)
            .filter(
                LearningPattern.user_id == user_id,
                LearningPattern.pattern_type == "endpoint_pattern",
                LearningPattern.pattern_value == path_pattern,
                LearningPattern.vulnerability_type == vuln_type,
            )
            .first()
        )

        if existing:
            # Update existing pattern
            existing.success_count += 1
            existing.confidence_score = min(100, existing.confidence_score + 5)
            existing.last_seen = datetime.now(timezone.utc)
        else:
            # Create new pattern
            pattern = LearningPattern(
                user_id=user_id,
                pattern_type="endpoint_pattern",
                vulnerability_type=vuln_type,
                pattern_value=path_pattern,
                confidence_score=50,
                success_count=1,
                target_domain=urlparse(vulnerability.matched_url or "").netloc,
                discovery_method=vulnerability.source,
            )
            db.add(pattern)

        db.commit()

    def _store_payload_pattern(
        self,
        db: Session,
        user_id: int,
        pattern_data: Dict,
        vulnerability: Vulnerability,
        vuln_type: str,
    ):
        """Store payload learning pattern."""
        payload_types = pattern_data.get("payload_types", [])

        for payload_type in payload_types:
            # Check if pattern already exists
            existing = (
                db.query(LearningPattern)
                .filter(
                    LearningPattern.user_id == user_id,
                    LearningPattern.pattern_type == "payload_type",
                    LearningPattern.pattern_value == payload_type,
                    LearningPattern.vulnerability_type == vuln_type,
                )
                .first()
            )

            if existing:
                existing.success_count += 1
                existing.confidence_score = min(100, existing.confidence_score + 5)
                existing.last_seen = datetime.now(timezone.utc)
            else:
                pattern = LearningPattern(
                    user_id=user_id,
                    pattern_type="payload_type",
                    vulnerability_type=vuln_type,
                    pattern_value=payload_type,
                    confidence_score=50,
                    success_count=1,
                    discovery_method=vulnerability.source,
                )
                db.add(pattern)

        db.commit()

    def _store_parameter_pattern(
        self,
        db: Session,
        user_id: int,
        pattern_data: Dict,
        vulnerability: Vulnerability,
        vuln_type: str,
    ):
        """Store parameter learning pattern."""
        vulnerable_params = pattern_data.get("vulnerable_parameters", [])

        for param in vulnerable_params:
            # Check if pattern already exists
            existing = (
                db.query(LearningPattern)
                .filter(
                    LearningPattern.user_id == user_id,
                    LearningPattern.pattern_type == "parameter_name",
                    LearningPattern.pattern_value == param,
                    LearningPattern.vulnerability_type == vuln_type,
                )
                .first()
            )

            if existing:
                existing.success_count += 1
                existing.confidence_score = min(100, existing.confidence_score + 5)
                existing.last_seen = datetime.now(timezone.utc)
            else:
                pattern = LearningPattern(
                    user_id=user_id,
                    pattern_type="parameter_name",
                    vulnerability_type=vuln_type,
                    pattern_value=param,
                    confidence_score=50,
                    success_count=1,
                    discovery_method=vulnerability.source,
                )
                db.add(pattern)

        db.commit()

    def _update_successful_payloads(
        self,
        db: Session,
        user_id: int,
        vulnerability: Vulnerability,
        validation: ExploitValidation,
    ):
        """Update successful payloads database."""
        payload = validation.payload or ""
        vuln_type = self._classify_vulnerability_type(vulnerability)

        if not payload:
            return

        # Check if payload already exists
        existing = (
            db.query(SuccessfulPayload)
            .filter(
                SuccessfulPayload.user_id == user_id,
                SuccessfulPayload.payload == payload,
                SuccessfulPayload.vulnerability_type == vuln_type,
            )
            .first()
        )

        if existing:
            # Update existing payload
            existing.usage_count += 1
            existing.confirmed_vulnerabilities += 1
            existing.success_rate = min(100, existing.success_rate + 10)
            existing.last_used = datetime.now(timezone.utc)
        else:
            # Create new payload entry
            successful_payload = SuccessfulPayload(
                user_id=user_id,
                payload=payload,
                vulnerability_type=vuln_type,
                context=validation.method,
                success_rate=75,  # Initial success rate
                usage_count=1,
                confirmed_vulnerabilities=1,
                target_patterns=json.dumps(
                    [urlparse(vulnerability.matched_url or "").netloc]
                ),
            )
            db.add(successful_payload)

        db.commit()

    def _update_high_value_endpoints(
        self,
        db: Session,
        user_id: int,
        vulnerability: Vulnerability,
        validation: Optional[ExploitValidation],
    ):
        """Update high-value endpoints database."""
        if not vulnerability.matched_url:
            return

        parsed = urlparse(vulnerability.matched_url)
        path = parsed.path
        vuln_type = self._classify_vulnerability_type(vulnerability)

        # Classify endpoint type
        endpoint_type = self._classify_endpoint_type(path, vuln_type)

        # Create generalized pattern
        pattern = self._generalize_path(path)

        # Check if endpoint pattern already exists
        existing = (
            db.query(HighValueEndpoint)
            .filter(
                HighValueEndpoint.user_id == user_id,
                HighValueEndpoint.endpoint_pattern == pattern,
                HighValueEndpoint.endpoint_type == endpoint_type,
            )
            .first()
        )

        if existing:
            # Update existing endpoint
            existing.vulnerabilities_found += 1
            if vulnerability.severity.lower() in ["critical", "high"]:
                existing.critical_vulnerabilities += 1
            existing.priority_score = min(100, existing.priority_score + 10)
            existing.last_discovery = datetime.now(timezone.utc)
        else:
            # Create new endpoint entry
            high_value_endpoint = HighValueEndpoint(
                user_id=user_id,
                endpoint_pattern=pattern,
                endpoint_type=endpoint_type,
                priority_score=60,  # Initial priority
                vulnerabilities_found=1,
                critical_vulnerabilities=(
                    1 if vulnerability.severity.lower() in ["critical", "high"] else 0
                ),
                confirmation_rate=(
                    100
                    if validation and validation.validation_status == "confirmed"
                    else 50
                ),
            )
            db.add(high_value_endpoint)

        db.commit()

    def _classify_vulnerability_type(self, vulnerability: Vulnerability) -> str:
        """Classify vulnerability type from template ID."""
        template_id = vulnerability.template_id.lower()

        if "xss" in template_id or "cross-site scripting" in template_id:
            return "xss"
        elif "sqli" in template_id or "sql injection" in template_id:
            return "sqli"
        elif "ssrf" in template_id or "server-side request forgery" in template_id:
            return "ssrf"
        elif "rce" in template_id or "remote code execution" in template_id:
            return "rce"
        elif "lfi" in template_id or "local file inclusion" in template_id:
            return "lfi"
        elif "rfi" in template_id or "remote file inclusion" in template_id:
            return "rfi"
        else:
            return "unknown"

    def _classify_endpoint_type(self, path: str, vuln_type: str) -> str:
        """Classify endpoint type based on path and vulnerability."""
        path_lower = path.lower()

        # Admin endpoints
        if any(
            admin_word in path_lower
            for admin_word in ["admin", "dashboard", "panel", "manage"]
        ):
            return "admin"

        # API endpoints
        if any(
            api_word in path_lower
            for api_word in ["api", "v1", "v2", "rest", "graphql"]
        ):
            return "api"

        # Debug endpoints
        if any(
            debug_word in path_lower
            for debug_word in ["debug", "test", "dev", "staging"]
        ):
            return "debug"

        # Backup endpoints
        if any(
            backup_word in path_lower
            for backup_word in ["backup", "bak", "old", "archive"]
        ):
            return "backup"

        # Config endpoints
        if any(
            config_word in path_lower
            for config_word in ["config", "settings", "setup", "install"]
        ):
            return "config"

        # Upload endpoints
        if any(
            upload_word in path_lower for upload_word in ["upload", "file", "import"]
        ):
            return "upload"

        return "general"

    def get_similar_findings(
        self, db: Session, user_id: int, current_vulnerability: Vulnerability
    ) -> Dict[str, List[Dict]]:
        """Get similar past findings for current vulnerability."""
        similar_findings = {
            "endpoint_patterns": [],
            "payload_suggestions": [],
            "parameter_risks": [],
        }

        vuln_type = self._classify_vulnerability_type(current_vulnerability)

        # Get similar endpoint patterns
        if current_vulnerability.matched_url:
            path_pattern = self._generalize_path(
                urlparse(current_vulnerability.matched_url).path
            )

            endpoint_patterns = (
                db.query(LearningPattern)
                .filter(
                    LearningPattern.user_id == user_id,
                    LearningPattern.pattern_type == "endpoint_pattern",
                    LearningPattern.vulnerability_type == vuln_type,
                    LearningPattern.confidence_score >= 60,
                )
                .order_by(LearningPattern.confidence_score.desc())
                .limit(5)
                .all()
            )

            similar_findings["endpoint_patterns"] = [
                {
                    "pattern": p.pattern_value,
                    "confidence": p.confidence_score,
                    "success_count": p.success_count,
                    "last_seen": p.last_seen,
                }
                for p in endpoint_patterns
            ]

        # Get successful payloads
        payloads = (
            db.query(SuccessfulPayload)
            .filter(
                SuccessfulPayload.user_id == user_id,
                SuccessfulPayload.vulnerability_type == vuln_type,
                SuccessfulPayload.success_rate >= 60,
            )
            .order_by(SuccessfulPayload.success_rate.desc())
            .limit(5)
            .all()
        )

        similar_findings["payload_suggestions"] = [
            {
                "payload": p.payload,
                "success_rate": p.success_rate,
                "usage_count": p.usage_count,
                "context": p.context,
            }
            for p in payloads
        ]

        # Get parameter risks
        if current_vulnerability.matched_url:
            params = self._extract_parameter_patterns(current_vulnerability.matched_url)
            vulnerable_params = params.get("vulnerable_parameters", [])

            for param in vulnerable_params[:3]:  # Limit to top 3
                param_patterns = (
                    db.query(LearningPattern)
                    .filter(
                        LearningPattern.user_id == user_id,
                        LearningPattern.pattern_type == "parameter_name",
                        LearningPattern.pattern_value == param,
                        LearningPattern.vulnerability_type == vuln_type,
                    )
                    .all()
                )

                if param_patterns:
                    similar_findings["parameter_risks"].append(
                        {
                            "parameter": param,
                            "risk_score": max(
                                p.confidence_score for p in param_patterns
                            ),
                            "vulnerability_types": list(
                                set(p.vulnerability_type for p in param_patterns)
                            ),
                        }
                    )

        return similar_findings

    def get_learning_insights(self, db: Session, user_id: int) -> Dict[str, Any]:
        """Get comprehensive learning insights for a user."""
        insights = {
            "total_patterns": 0,
            "top_vulnerability_types": [],
            "high_value_endpoints": [],
            "successful_payloads": [],
            "learning_progress": {},
        }

        # Count total patterns
        total_patterns = (
            db.query(LearningPattern).filter(LearningPattern.user_id == user_id).count()
        )
        insights["total_patterns"] = total_patterns

        # Get top vulnerability types
        vuln_types = (
            db.query(
                LearningPattern.vulnerability_type,
                db.func.count(LearningPattern.id).label("count"),
            )
            .filter(LearningPattern.user_id == user_id)
            .group_by(LearningPattern.vulnerability_type)
            .order_by(db.func.count(LearningPattern.id).desc())
            .limit(5)
            .all()
        )

        insights["top_vulnerability_types"] = [
            {"type": vt[0], "count": vt[1]} for vt in vuln_types
        ]

        # Get high-value endpoints
        high_value = (
            db.query(HighValueEndpoint)
            .filter(HighValueEndpoint.user_id == user_id)
            .order_by(HighValueEndpoint.priority_score.desc())
            .limit(10)
            .all()
        )

        insights["high_value_endpoints"] = [
            {
                "pattern": h.endpoint_pattern,
                "type": h.endpoint_type,
                "priority": h.priority_score,
                "vulnerabilities": h.vulnerabilities_found,
            }
            for h in high_value
        ]

        # Get successful payloads
        payloads = (
            db.query(SuccessfulPayload)
            .filter(SuccessfulPayload.user_id == user_id)
            .order_by(SuccessfulPayload.success_rate.desc())
            .limit(10)
            .all()
        )

        insights["successful_payloads"] = [
            {
                "payload": (
                    p.payload[:100] + "..." if len(p.payload) > 100 else p.payload
                ),
                "type": p.vulnerability_type,
                "success_rate": p.success_rate,
                "usage_count": p.usage_count,
            }
            for p in payloads
        ]

        return insights


# Global learning service instance
learning_service = IntelligenceLearningService()
