"""AI-powered Nuclei template generator service."""

import json
import logging
from typing import Any, Dict, Optional

from app.services.ai_service import _get_model_response, _is_ai_enabled
from app.core.config import settings

logger = logging.getLogger(__name__)

TEMPLATE_GENERATOR_PROMPT = """
You are an expert Security Researcher and Nuclei template engineer.
Your task is to generate a valid, functional, and high-quality Nuclei YAML template 
based on the provided vulnerability details, HTTP requests, or descriptions.

STRICT RULES:
1. Output ONLY the valid YAML template. No explanations, no markdown code blocks.
2. Ensure the template follows the standard Nuclei schema.
3. Use appropriate matchers (status, word, regex) to ensure high confidence and low false positives.
4. Include detailed 'info' metadata: name, author, severity, description, reference, and tags.
5. If a request/response is provided, use it to build exact matchers and the correct HTTP request path.
6. The 'id' should be a slugified version of the template name.

SCHEMA HINTS:
- Use 'http:' or 'requests:' depending on the complexity.
- Matchers should be logically grouped (AND/OR).
- Prefer 'stop-at-first-match: true' for performance where applicable.
"""


class AITemplateGenerator:
    """Service to generate Nuclei templates using AI."""

    async def generate_from_description(self, description: str) -> Optional[str]:
        """Generate a Nuclei template from a natural language description."""

        if not _is_ai_enabled(task="report"):
            logger.error("AI report provider not configured for template generation")
            return None

        user_message = json.dumps(
            {
                "task": "generate_nuclei_template",
                "source_type": "description",
                "content": description,
            }
        )

        try:
            template_yaml = await _get_model_response(
                prompt=user_message,
                system_instruction=TEMPLATE_GENERATOR_PROMPT,
                task="report",
            )

            # Clean up potential markdown blocks if AI ignored instructions
            if "```yaml" in template_yaml:
                template_yaml = (
                    template_yaml.split("```yaml")[1].split("```")[0].strip()
                )
            elif "```" in template_yaml:
                template_yaml = template_yaml.split("```")[1].split("```")[0].strip()

            return template_yaml.strip()

        except Exception as e:
            logger.error(f"Failed to generate template from description: {e}")
            return None

    async def generate_from_http(
        self, request: str, response: Optional[str] = None
    ) -> Optional[str]:
        """Generate a Nuclei template from raw HTTP request/response."""

        if not _is_ai_enabled(task="report"):
            logger.error("AI report provider not configured for template generation")
            return None

        user_message = json.dumps(
            {
                "task": "generate_nuclei_template",
                "source_type": "http_traffic",
                "request": request,
                "response": response,
            }
        )

        try:
            template_yaml = await _get_model_response(
                prompt=user_message,
                system_instruction=TEMPLATE_GENERATOR_PROMPT,
                task="report",
            )

            # Clean up markdown
            if "```yaml" in template_yaml:
                template_yaml = (
                    template_yaml.split("```yaml")[1].split("```")[0].strip()
                )
            elif "```" in template_yaml:
                template_yaml = template_yaml.split("```")[1].split("```")[0].strip()

            return template_yaml.strip()

        except Exception as e:
            logger.error(f"Failed to generate template from HTTP: {e}")
            return None


template_generator = AITemplateGenerator()
