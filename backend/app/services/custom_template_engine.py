"""Custom Nuclei Template Engine for user-defined vulnerability templates."""

import json
import logging
import os
import tempfile
import yaml
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.custom_templates import CustomNucleiTemplate, CustomTemplateResult
from app.services.tool_executor import execute_with_retry

logger = logging.getLogger(__name__)


class CustomTemplateEngine:
    """Engine for managing and executing custom Nuclei templates."""

    def __init__(self):
        self.template_dir = tempfile.mkdtemp(prefix="nuclei_custom_")
        self.required_fields = ["id", "info"]
        self.valid_severities = ["info", "low", "medium", "high", "critical"]

    def create_template(
        self,
        db: Session,
        user_id: int,
        name: str,
        template_content: str,
        author: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        is_public: bool = False,
    ) -> Tuple[bool, str, Optional[CustomNucleiTemplate]]:
        """Create a new custom Nuclei template."""

        try:
            # Validate YAML syntax
            try:
                yaml_content = yaml.safe_load(template_content)
            except yaml.YAMLError as e:
                return False, f"Invalid YAML syntax: {str(e)}", None

            # Validate required fields
            validation_result = self._validate_template_structure(yaml_content)
            if not validation_result[0]:
                return False, validation_result[1], None

            # Extract template info
            info = yaml_content.get("info", {})
            severity = info.get("severity", "info").lower()
            template_type = yaml_content.get("type", "file")

            # Validate severity
            if severity not in self.valid_severities:
                return (
                    False,
                    f"Invalid severity. Must be one of: {self.valid_severities}",
                    None,
                )

            # Create template record
            template = CustomNucleiTemplate(
                user_id=user_id,
                name=name,
                author=author or "Anonymous",
                description=description or "",
                severity=severity,
                template_content=template_content,
                template_type=template_type,
                tags=json.dumps(tags or []),
                cwe_ids=json.dumps(info.get("classification", {}).get("cwe-id", [])),
                category=self._extract_category(yaml_content),
                is_valid=True,
                is_public=is_public,
            )

            db.add(template)
            db.commit()
            db.refresh(template)

            logger.info(f"Created custom template '{name}' for user {user_id}")
            return True, "Template created successfully", template

        except Exception as e:
            logger.error(f"Failed to create custom template: {e}")
            return False, f"Failed to create template: {str(e)}", None

    def _validate_template_structure(self, yaml_content: Dict) -> Tuple[bool, str]:
        """Validate Nuclei template structure."""

        # Check required fields
        if "id" not in yaml_content:
            return False, "Template missing required 'id' field"

        if "info" not in yaml_content:
            return False, "Template missing required 'info' section"

        info = yaml_content["info"]

        if "name" not in info:
            return False, "Template info missing required 'name' field"

        if "severity" not in info:
            return False, "Template info missing required 'severity' field"

        # Check for at least one request/matcher
        if not any(
            key in yaml_content
            for key in ["requests", "http", "dns", "network", "file"]
        ):
            return False, "Template must contain at least one request/matcher section"

        return True, "Template structure is valid"

    def _extract_category(self, yaml_content: Dict) -> str:
        """Extract template category from content."""

        # Try to determine category from template content
        if any(key in yaml_content for key in ["http", "requests"]):
            return "web"
        elif "dns" in yaml_content:
            return "dns"
        elif "network" in yaml_content:
            return "network"
        elif "file" in yaml_content:
            return "file"
        elif "workflow" in yaml_content:
            return "workflow"
        else:
            return "other"

    def update_template(
        self, db: Session, user_id: int, template_id: int, updates: Dict
    ) -> Tuple[bool, str]:
        """Update an existing custom template."""

        try:
            template = (
                db.query(CustomNucleiTemplate)
                .filter(
                    CustomNucleiTemplate.id == template_id,
                    CustomNucleiTemplate.user_id == user_id,
                )
                .first()
            )

            if not template:
                return False, "Template not found"

            # Update fields
            if "name" in updates:
                template.name = updates["name"]

            if "description" in updates:
                template.description = updates["description"]

            if "template_content" in updates:
                # Validate new content
                try:
                    yaml_content = yaml.safe_load(updates["template_content"])
                    validation_result = self._validate_template_structure(yaml_content)
                    if not validation_result[0]:
                        return False, validation_result[1]

                    template.template_content = updates["template_content"]
                    template.is_valid = True
                    template.validation_error = None
                except yaml.YAMLError as e:
                    template.is_valid = False
                    template.validation_error = str(e)
                    return False, f"Invalid YAML syntax: {str(e)}"

            if "tags" in updates:
                template.tags = json.dumps(updates["tags"])

            if "is_public" in updates:
                template.is_public = updates["is_public"]

            if "is_active" in updates:
                template.is_active = updates["is_active"]

            template.updated_at = datetime.now(timezone.utc)
            db.commit()

            return True, "Template updated successfully"

        except Exception as e:
            logger.error(f"Failed to update template {template_id}: {e}")
            return False, f"Failed to update template: {str(e)}"

    def delete_template(
        self, db: Session, user_id: int, template_id: int
    ) -> Tuple[bool, str]:
        """Delete a custom template."""

        try:
            template = (
                db.query(CustomNucleiTemplate)
                .filter(
                    CustomNucleiTemplate.id == template_id,
                    CustomNucleiTemplate.user_id == user_id,
                )
                .first()
            )

            if not template:
                return False, "Template not found"

            db.delete(template)
            db.commit()

            return True, "Template deleted successfully"

        except Exception as e:
            logger.error(f"Failed to delete template {template_id}: {e}")
            return False, f"Failed to delete template: {str(e)}"

    def run_template(
        self, db: Session, template_id: int, target_urls: List[str], scan_id: int
    ) -> Tuple[bool, str, List[Dict]]:
        """Run a custom template against target URLs."""

        try:
            template = (
                db.query(CustomNucleiTemplate)
                .filter(CustomNucleiTemplate.id == template_id)
                .first()
            )

            if not template:
                return False, "Template not found", []

            if not template.is_valid:
                return False, f"Template is invalid: {template.validation_error}", []

            # Write template to temporary file
            template_file = os.path.join(
                self.template_dir, f"template_{template_id}.yaml"
            )
            with open(template_file, "w") as f:
                f.write(template.template_content)

            # Run nuclei with custom template
            targets_file = os.path.join(self.template_dir, f"targets_{template_id}.txt")
            with open(targets_file, "w") as f:
                for url in target_urls:
                    f.write(f"{url}\n")

            cmd = [
                "nuclei",
                "-t",
                template_file,
                "-l",
                targets_file,
                "-json",
                "-silent",
                "-no-color",
            ]

            result = execute_with_retry(cmd, timeout=300)

            if result.status != "success":
                logger.error(f"Nuclei execution failed: {result.error}")
                return False, f"Template execution failed: {result.error}", []

            # Parse results
            findings = []
            if result.stdout:
                findings = self._parse_nuclei_output(
                    result.stdout, template_id, scan_id
                )

            # Store results in database
            stored_results = []
            for finding in findings:
                result_record = CustomTemplateResult(
                    template_id=template_id,
                    scan_id=scan_id,
                    matched_url=finding.get("matched-url", ""),
                    matched_at=finding.get("matched-at", ""),
                    template_id_ref=finding.get("template-id", ""),
                    info_name=finding.get("info", {}).get("name", ""),
                    info_severity=finding.get("info", {}).get("severity", "info"),
                    extractors_result=json.dumps(finding.get("extractors-results", {})),
                    request=json.dumps(finding.get("request", {})),
                    response=json.dumps(finding.get("response", {})),
                    confidence=70,  # Default confidence for custom templates
                )
                db.add(result_record)
                stored_results.append(result_record)

            if stored_results:
                db.commit()

            # Update template usage stats
            template.usage_count += 1
            template.successful_detections += len(stored_results)
            template.last_used = datetime.now(timezone.utc)
            db.commit()

            # Cleanup temporary files
            try:
                os.remove(template_file)
                os.remove(targets_file)
            except:
                pass

            return (
                True,
                f"Template executed successfully. Found {len(stored_results)} matches.",
                findings,
            )

        except Exception as e:
            logger.error(f"Failed to run template {template_id}: {e}")
            return False, f"Failed to run template: {str(e)}", []

    def _parse_nuclei_output(
        self, output: str, template_id: int, scan_id: int
    ) -> List[Dict]:
        """Parse Nuclei JSON output."""
        findings = []

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse Nuclei output line: {line}")
                continue

        return findings

    def get_user_templates(
        self,
        db: Session,
        user_id: int,
        include_public: bool = True,
        only_active: bool = True,
    ) -> List[CustomNucleiTemplate]:
        """Get templates for a user."""

        query = db.query(CustomNucleiTemplate).filter(
            CustomNucleiTemplate.user_id == user_id
        )

        if include_public:
            query = query.union(
                db.query(CustomNucleiTemplate).filter(
                    CustomNucleiTemplate.is_public == True,
                    CustomNucleiTemplate.is_active == True,
                )
            )

        if only_active:
            query = query.filter(CustomNucleiTemplate.is_active == True)

        return query.order_by(CustomNucleiTemplate.created_at.desc()).all()

    def get_template_results(
        self, db: Session, template_id: int, limit: int = 100
    ) -> List[CustomTemplateResult]:
        """Get results for a specific template."""

        return (
            db.query(CustomTemplateResult)
            .filter(CustomTemplateResult.template_id == template_id)
            .order_by(CustomTemplateResult.created_at.desc())
            .limit(limit)
            .all()
        )

    def get_public_templates(
        self, db: Session, limit: int = 50
    ) -> List[CustomNucleiTemplate]:
        """Get public templates from all users."""

        return (
            db.query(CustomNucleiTemplate)
            .filter(
                CustomNucleiTemplate.is_public == True,
                CustomNucleiTemplate.is_active == True,
                CustomNucleiTemplate.is_valid == True,
            )
            .order_by(CustomNucleiTemplate.successful_detections.desc())
            .limit(limit)
            .all()
        )

    def search_templates(
        self, db: Session, user_id: int, query: str, include_public: bool = True
    ) -> List[CustomNucleiTemplate]:
        """Search templates by name, description, or tags."""

        search_pattern = f"%{query}%"

        user_templates = (
            db.query(CustomNucleiTemplate)
            .filter(
                CustomNucleiTemplate.user_id == user_id,
                CustomNucleiTemplate.is_active == True,
            )
            .filter(
                (CustomNucleiTemplate.name.ilike(search_pattern))
                | (CustomNucleiTemplate.description.ilike(search_pattern))
                | (CustomNucleiTemplate.tags.ilike(search_pattern))
            )
        )

        if include_public:
            public_templates = (
                db.query(CustomNucleiTemplate)
                .filter(
                    CustomNucleiTemplate.is_public == True,
                    CustomNucleiTemplate.is_active == True,
                )
                .filter(
                    (CustomNucleiTemplate.name.ilike(search_pattern))
                    | (CustomNucleiTemplate.description.ilike(search_pattern))
                    | (CustomNucleiTemplate.tags.ilike(search_pattern))
                )
            )
            return user_templates.union(public_templates).all()

        return user_templates.all()


# Global template engine instance
template_engine = CustomTemplateEngine()
