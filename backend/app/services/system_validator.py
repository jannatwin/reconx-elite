"""System validation and health checks for ReconX Elite."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.database import get_sessionmaker
from app.core.config import settings
from app.services.logging_service import reconx_logger

logger = logging.getLogger(__name__)


class SystemValidator:
    """Comprehensive system validation and health monitoring."""

    def __init__(self):
        self.validation_checks = {
            "database": self._validate_database,
            "ai_service": self._validate_ai_service,
            "models": self._validate_models,
            "services": self._validate_services,
            "security": self._validate_security,
        }

    async def run_full_validation(self) -> Dict[str, Any]:
        """Run comprehensive system validation."""

        results = {
            "validation_timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": "healthy",
            "checks": {},
            "errors": [],
            "warnings": [],
        }

        for check_name, check_func in self.validation_checks.items():
            try:
                check_result = await check_func()
                results["checks"][check_name] = check_result

                if check_result["status"] == "error":
                    results["overall_status"] = "unhealthy"
                    results["errors"].append(
                        f"{check_name}: {check_result.get('message', 'Unknown error')}"
                    )
                elif check_result["status"] == "warning":
                    if results["overall_status"] == "healthy":
                        results["overall_status"] = "degraded"
                    results["warnings"].append(
                        f"{check_name}: {check_result.get('message', 'Warning')}"
                    )

            except Exception as e:
                logger.error(f"Validation check {check_name} failed: {e}")
                results["checks"][check_name] = {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                results["overall_status"] = "unhealthy"
                results["errors"].append(f"{check_name}: {str(e)}")

        # Log validation results
        reconx_logger.log_structured(
            level="info" if results["overall_status"] == "healthy" else "warning",
            event="system_validation",
            data=results,
        )

        return results

    async def _validate_database(self) -> Dict[str, Any]:
        """Validate database connectivity and schema."""

        db = get_sessionmaker()()

        try:
            # Test basic connectivity
            result = db.execute(text("SELECT 1")).scalar()

            if result != 1:
                return {
                    "status": "error",
                    "message": "Database query failed",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            # Check critical tables exist
            critical_tables = ["users", "targets", "scans", "vulnerabilities"]
            missing_tables = []

            for table in critical_tables:
                try:
                    db.execute(text(f"SELECT COUNT(*) FROM {table} LIMIT 1"))
                except Exception:
                    missing_tables.append(table)

            if missing_tables:
                return {
                    "status": "error",
                    "message": f"Missing critical tables: {', '.join(missing_tables)}",
                    "missing_tables": missing_tables,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            return {
                "status": "healthy",
                "message": "Database connectivity and schema validated",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Database validation failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        finally:
            db.close()

    async def _validate_ai_service(self) -> Dict[str, Any]:
        """Validate AI service configuration and availability."""

        try:
            from app.services.ai_service import (
                _is_ai_enabled,
                get_model_status_snapshot,
                MODEL_MAP,
            )

            if not _is_ai_enabled("scan") and not _is_ai_enabled("report"):
                return {
                    "status": "warning",
                    "message": "AI providers are not configured - AI features disabled",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            snapshot = get_model_status_snapshot()
            return {
                "status": "healthy",
                "message": "AI service configured and roster loaded",
                "provider": snapshot["provider"],
                "model_count": len(MODEL_MAP),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"AI service validation failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def _validate_models(self) -> Dict[str, Any]:
        """Validate all model imports and relationships."""

        try:
            # Test importing all models
            from app.models import (
                User,
                Target,
                Scan,
                Vulnerability,
                ExploitValidation,
                OutOfBandInteraction,
                LearningPattern,
                SuccessfulPayload,
                HighValueEndpoint,
                CustomNucleiTemplate,
                AIReport,
            )

            # Check if all models can be instantiated (basic structure check)
            models_to_check = [
                User,
                Target,
                Scan,
                Vulnerability,
                ExploitValidation,
                OutOfBandInteraction,
                LearningPattern,
                SuccessfulPayload,
                HighValueEndpoint,
                CustomNucleiTemplate,
                AIReport,
            ]

            for model_class in models_to_check:
                # Just check if the model class exists and has required attributes
                if not hasattr(model_class, "__tablename__"):
                    return {
                        "status": "error",
                        "message": f"Model {model_class.__name__} missing __tablename__",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

            return {
                "status": "healthy",
                "message": "All models imported and structured correctly",
                "models_count": len(models_to_check),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Model validation failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def _validate_services(self) -> Dict[str, Any]:
        """Validate all service imports and basic functionality."""

        try:
            # Test importing all services
            from app.services import (
                ai_service,
                exploit_validator,
                out_of_band_service,
                manual_tester,
                intelligence_learning,
                custom_template_engine,
                logging_service,
            )

            services_to_check = [
                ("ai_service", ai_service),
                ("exploit_validator", exploit_validator),
                ("out_of_band_service", out_of_band_service),
                ("manual_tester", manual_tester),
                ("intelligence_learning", intelligence_learning),
                ("custom_template_engine", custom_template_engine),
                ("logging_service", logging_service),
            ]

            for service_name, service_module in services_to_check:
                if not service_module:
                    return {
                        "status": "error",
                        "message": f"Service {service_name} import failed",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

            return {
                "status": "healthy",
                "message": "All services imported successfully",
                "services_count": len(services_to_check),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Service validation failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def _validate_security(self) -> Dict[str, Any]:
        """Validate security configurations."""

        try:
            security_issues = []

            # Check for default secrets
            if settings.jwt_secret_key == "change-me-in-production":
                security_issues.append("Default JWT secret key detected")

            # Check if .env is properly configured
            if not settings.gemini_api_key:
                security_issues.append("Gemini API key not configured")

            # Check CORS settings
            if (
                "localhost" in settings.cors_allowed_origins
                and "localhost" in settings.cors_allowed_origins
            ):
                security_issues.append(
                    "Localhost CORS origins detected (OK for development)"
                )

            # Check rate limits
            try:
                scan_limit_value = int(str(settings.scan_rate_limit).split("/", 1)[0])
            except (TypeError, ValueError):
                scan_limit_value = 0
            if scan_limit_value > 100:
                security_issues.append("High scan rate limit detected")

            if security_issues:
                return {
                    "status": "warning",
                    "message": "Security configuration issues detected",
                    "issues": security_issues,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            return {
                "status": "healthy",
                "message": "Security configuration validated",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Security validation failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def validate_specific_component(self, component: str) -> Dict[str, Any]:
        """Validate a specific system component."""

        if component not in self.validation_checks:
            return {
                "status": "error",
                "message": f"Unknown component: {component}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        try:
            return await self.validation_checks[component]()
        except Exception as e:
            return {
                "status": "error",
                "message": f"Component {component} validation failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }


# Global validator instance
system_validator = SystemValidator()
