import json
import logging
from typing import Dict, List, Optional, Any
from enum import Enum

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class TicketingPlatform(str, Enum):
    JIRA = "jira"
    GITHUB = "github"
    GITLAB = "gitlab"


class JiraConfig(BaseModel):
    url: str = Field(..., description="Jira instance URL")
    username: str = Field(..., description="Jira username or email")
    api_token: str = Field(..., description="Jira API token")
    project_key: str = Field(..., description="Jira project key (e.g., 'SEC')")
    issue_type: str = Field(default="Bug", description="Issue type to create")


class GitHubConfig(BaseModel):
    token: str = Field(..., description="GitHub personal access token")
    repository: str = Field(..., description="Repository in format 'owner/repo'")
    assignee: Optional[str] = Field(None, description="GitHub username to assign issues to")


class GitLabConfig(BaseModel):
    url: str = Field(default="https://gitlab.com", description="GitLab instance URL")
    token: str = Field(..., description="GitLab personal access token")
    project_id: str = Field(..., description="GitLab project ID or path")
    assignee_id: Optional[int] = Field(None, description="GitLab user ID to assign issues to")


class TicketingService:
    """Service for integrating with external ticketing systems."""
    
    def __init__(self, platform: TicketingPlatform, config: Dict[str, Any]):
        self.platform = platform
        self.config = config
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def create_vulnerability_ticket(
        self, 
        vulnerability: Dict[str, Any],
        target_domain: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a ticket for a vulnerability in the configured platform."""
        
        if self.platform == TicketingPlatform.JIRA:
            return await self._create_jira_ticket(vulnerability, target_domain, additional_context)
        elif self.platform == TicketingPlatform.GITHUB:
            return await self._create_github_issue(vulnerability, target_domain, additional_context)
        elif self.platform == TicketingPlatform.GITLAB:
            return await self._create_gitlab_issue(vulnerability, target_domain, additional_context)
        else:
            raise ValueError(f"Unsupported platform: {self.platform}")
    
    async def _create_jira_ticket(
        self, 
        vulnerability: Dict[str, Any],
        target_domain: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a Jira issue for the vulnerability."""
        
        config = JiraConfig(**self.config)
        
        # Build Jira issue description
        description = self._build_jira_description(vulnerability, target_domain, additional_context)
        
        # Determine priority based on severity
        severity = vulnerability.get('severity', 'low').lower()
        priority_map = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Lowest'
        }
        priority = priority_map.get(severity, 'Medium')
        
        # Create issue payload
        payload = {
            "fields": {
                "project": {"key": config.project_key},
                "summary": f"[{severity.upper()}] {vulnerability.get('template_id', 'Unknown')} - {target_domain}",
                "description": description,
                "issuetype": {"name": config.issue_type},
                "priority": {"name": priority},
                "labels": [f"reconx-{severity}", "security", target_domain]
            }
        }
        
        headers = {
            "Authorization": f"Basic {self._encode_credentials(config.username, config.api_token)}",
            "Content-Type": "application/json"
        }
        
        try:
            response = await self.client.post(
                f"{config.url}/rest/api/2/issue",
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            
            issue_data = response.json()
            return {
                "platform": "jira",
                "ticket_id": issue_data.get("key"),
                "ticket_url": f"{config.url}/browse/{issue_data.get('key')}",
                "status": "created"
            }
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to create Jira issue: {e.response.text}")
            raise Exception(f"Jira API error: {e.response.status_code} - {e.response.text}")
    
    async def _create_github_issue(
        self, 
        vulnerability: Dict[str, Any],
        target_domain: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a GitHub issue for the vulnerability."""
        
        config = GitHubConfig(**self.config)
        
        # Build GitHub issue body
        body = self._build_github_body(vulnerability, target_domain, additional_context)
        
        # Create issue payload
        payload = {
            "title": f"[{vulnerability.get('severity', 'low').upper()}] {vulnerability.get('template_id', 'Unknown')} - {target_domain}",
            "body": body,
            "labels": [f"reconx-{vulnerability.get('severity', 'low')}", "security", target_domain]
        }
        
        if config.assignee:
            payload["assignees"] = [config.assignee]
        
        headers = {
            "Authorization": f"token {config.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = await self.client.post(
                f"https://api.github.com/repos/{config.repository}/issues",
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            
            issue_data = response.json()
            return {
                "platform": "github",
                "ticket_id": str(issue_data.get("number")),
                "ticket_url": issue_data.get("html_url"),
                "status": "created"
            }
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to create GitHub issue: {e.response.text}")
            raise Exception(f"GitHub API error: {e.response.status_code} - {e.response.text}")
    
    async def _create_gitlab_issue(
        self, 
        vulnerability: Dict[str, Any],
        target_domain: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a GitLab issue for the vulnerability."""
        
        config = GitLabConfig(**self.config)
        
        # Build GitLab issue description
        description = self._build_gitlab_description(vulnerability, target_domain, additional_context)
        
        # Create issue payload
        payload = {
            "title": f"[{vulnerability.get('severity', 'low').upper()}] {vulnerability.get('template_id', 'Unknown')} - {target_domain}",
            "description": description,
            "labels": [f"reconx-{vulnerability.get('severity', 'low')}", "security", target_domain]
        }
        
        if config.assignee_id:
            payload["assignee_id"] = config.assignee_id
        
        headers = {
            "Authorization": f"Bearer {config.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = await self.client.post(
                f"{config.url}/api/v4/projects/{config.project_id}/issues",
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            
            issue_data = response.json()
            return {
                "platform": "gitlab",
                "ticket_id": str(issue_data.get("iid")),
                "ticket_url": issue_data.get("web_url"),
                "status": "created"
            }
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to create GitLab issue: {e.response.text}")
            raise Exception(f"GitLab API error: {e.response.status_code} - {e.response.text}")
    
    def _build_jira_description(
        self, 
        vulnerability: Dict[str, Any], 
        target_domain: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build Jira issue description with vulnerability details."""
        
        description = f"""h2. Vulnerability Details

*Target Domain:* {target_domain}
*Template ID:* {vulnerability.get('template_id', 'Unknown')}
*Severity:* {vulnerability.get('severity', 'Unknown')}
*Confidence:* {vulnerability.get('confidence', 'Unknown')}
*Source:* {vulnerability.get('source', 'Unknown')}

h3. Description
{vulnerability.get('description', 'No description available')}

h3. Affected URL
{vulnerability.get('matched_url', 'Unknown')}

h3. Evidence
{code:json}
{json.dumps(vulnerability.get('evidence_json', {}), indent=2)}
{code}

"""
        
        if additional_context:
            description += "h3. Additional Context\n"
            for key, value in additional_context.items():
                description += f"*{key.replace('_', ' ').title()}:* {value}\n"
        
        description += "\n---\n*This issue was automatically created by ReconX Elite*"
        
        return description
    
    def _build_github_body(
        self, 
        vulnerability: Dict[str, Any], 
        target_domain: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build GitHub issue body with vulnerability details."""
        
        body = f"""## Vulnerability Details

**Target Domain:** {target_domain}
**Template ID:** {vulnerability.get('template_id', 'Unknown')}
**Severity:** {vulnerability.get('severity', 'Unknown')}
**Confidence:** {vulnerability.get('confidence', 'Unknown')}
**Source:** {vulnerability.get('source', 'Unknown')}

### Description
{vulnerability.get('description', 'No description available')}

### Affected URL
{vulnerability.get('matched_url', 'Unknown')}

### Evidence
```json
{json.dumps(vulnerability.get('evidence_json', {}), indent=2)}
```

"""
        
        if additional_context:
            body += "### Additional Context\n"
            for key, value in additional_context.items():
                body += f"**{key.replace('_', ' ').title()}:** {value}\n"
        
        body += "\n---\n*This issue was automatically created by ReconX Elite*"
        
        return body
    
    def _build_gitlab_description(
        self, 
        vulnerability: Dict[str, Any], 
        target_domain: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build GitLab issue description with vulnerability details."""
        
        description = f"""## Vulnerability Details

**Target Domain:** {target_domain}
**Template ID:** {vulnerability.get('template_id', 'Unknown')}
**Severity:** {vulnerability.get('severity', 'Unknown')}
**Confidence:** {vulnerability.get('confidence', 'Unknown')}
**Source:** {vulnerability.get('source', 'Unknown')}

### Description
{vulnerability.get('description', 'No description available')}

### Affected URL
{vulnerability.get('matched_url', 'Unknown')}

### Evidence
```json
{json.dumps(vulnerability.get('evidence_json', {}), indent=2)}
```

"""
        
        if additional_context:
            description += "### Additional Context\n"
            for key, value in additional_context.items():
                description += f"**{key.replace('_', ' ').title()}:** {value}\n"
        
        description += "\n---\n*This issue was automatically created by ReconX Elite*"
        
        return description
    
    def _encode_credentials(self, username: str, api_token: str) -> str:
        """Encode credentials for Basic Authentication."""
        import base64
        credentials = f"{username}:{api_token}"
        return base64.b64encode(credentials.encode()).decode()


async def create_vulnerability_ticket(
    platform: TicketingPlatform,
    config: Dict[str, Any],
    vulnerability: Dict[str, Any],
    target_domain: str,
    additional_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create a vulnerability ticket in the specified platform."""
    
    async with TicketingService(platform, config) as service:
        return await service.create_vulnerability_ticket(
            vulnerability, target_domain, additional_context
        )
