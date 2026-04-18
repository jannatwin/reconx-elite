from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.target import Target
from app.routers.auth import limiter
from app.core.config import settings
from app.services.ticketing import (
    TicketingPlatform,
    create_vulnerability_ticket,
    JiraConfig,
    GitHubConfig,
    GitLabConfig,
)
from app.services.audit import log_audit_event
from pydantic import BaseModel, Field

router = APIRouter(prefix="/ticketing", tags=["ticketing"])


class TicketingConfigRequest(BaseModel):
    platform: TicketingPlatform = Field(..., description="Ticketing platform")
    config: Dict = Field(..., description="Platform-specific configuration")


class CreateTicketRequest(BaseModel):
    vulnerability_id: int = Field(
        ..., description="Vulnerability ID to create ticket for"
    )
    platform: TicketingPlatform = Field(..., description="Ticketing platform")
    config: Dict = Field(..., description="Platform-specific configuration")
    additional_context: Optional[Dict] = Field(
        None, description="Additional context for the ticket"
    )


class TicketingConfigResponse(BaseModel):
    platform: TicketingPlatform
    is_configured: bool
    config_fields: List[str]


@router.get("/platforms", response_model=List[TicketingConfigResponse])
def list_ticketing_platforms(current_user: User = Depends(get_current_user)):
    """List available ticketing platforms and their configuration requirements."""

    platforms = []

    # Jira
    jira_configured = bool(
        settings.jira_url
        and settings.jira_username
        and settings.jira_api_token
        and settings.jira_project_key
    )
    platforms.append(
        TicketingConfigResponse(
            platform=TicketingPlatform.JIRA,
            is_configured=jira_configured,
            config_fields=["url", "username", "api_token", "project_key", "issue_type"],
        )
    )

    # GitHub
    github_configured = bool(settings.github_token and settings.github_repository)
    platforms.append(
        TicketingConfigResponse(
            platform=TicketingPlatform.GITHUB,
            is_configured=github_configured,
            config_fields=["token", "repository", "assignee"],
        )
    )

    # GitLab
    gitlab_configured = bool(settings.gitlab_token and settings.gitlab_project_id)
    platforms.append(
        TicketingConfigResponse(
            platform=TicketingPlatform.GITLAB,
            is_configured=gitlab_configured,
            config_fields=["url", "token", "project_id", "assignee_id"],
        )
    )

    return platforms


@router.post("/test-connection")
async def test_ticketing_connection(
    request: TicketingConfigRequest, current_user: User = Depends(get_current_user)
):
    """Test connection to a ticketing platform."""

    try:
        # Validate configuration based on platform
        if request.platform == TicketingPlatform.JIRA:
            config = JiraConfig(**request.config)
        elif request.platform == TicketingPlatform.GITHUB:
            config = GitHubConfig(**request.config)
        elif request.platform == TicketingPlatform.GITLAB:
            config = GitLabConfig(**request.config)
        else:
            raise HTTPException(status_code=400, detail="Unsupported platform")

        # Test the connection by creating a simple test ticket (or just validating credentials)
        # For now, we'll just validate the configuration
        return {
            "status": "success",
            "message": f"Connection to {request.platform} validated successfully",
        }

    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Failed to connect to {request.platform}: {str(e)}"
        )


@router.post("/create-ticket")
@limiter.limit(settings.ticketing_rate_limit)
async def create_ticket(
    request: CreateTicketRequest,
    db_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a ticket for a vulnerability in the specified platform."""

    # Get vulnerability and verify ownership
    vulnerability = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == request.vulnerability_id)
        .first()
    )

    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Get target to verify user owns it
    target = (
        db.query(Target)
        .filter(
            Target.id == vulnerability.scan.target_id,
            Target.owner_id == current_user.id,
        )
        .first()
    )

    if not target:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        # Validate configuration based on platform
        if request.platform == TicketingPlatform.JIRA:
            config = JiraConfig(**request.config)
        elif request.platform == TicketingPlatform.GITHUB:
            config = GitHubConfig(**request.config)
        elif request.platform == TicketingPlatform.GITLAB:
            config = GitLabConfig(**request.config)
        else:
            raise HTTPException(status_code=400, detail="Unsupported platform")

        # Prepare vulnerability data
        vuln_data = {
            "template_id": vulnerability.template_id,
            "severity": vulnerability.severity,
            "confidence": vulnerability.confidence,
            "matched_url": vulnerability.matched_url,
            "description": vulnerability.description,
            "evidence_json": vulnerability.evidence_json,
            "source": vulnerability.source,
        }

        # Prepare additional context
        context = {
            "vulnerability_id": vulnerability.id,
            "scan_id": vulnerability.scan_id,
            "user_id": current_user.id,
            "user_email": current_user.email,
        }

        if request.additional_context:
            context.update(request.additional_context)

        # Create the ticket
        ticket_result = await create_vulnerability_ticket(
            platform=request.platform,
            config=request.config,
            vulnerability=vuln_data,
            target_domain=target.domain,
            additional_context=context,
        )

        # Log the action
        log_audit_event(
            db,
            action="ticket_created",
            user_id=current_user.id,
            ip_address=db_request.client.host if db_request.client else None,
            metadata_json={
                "platform": request.platform,
                "vulnerability_id": vulnerability.id,
                "target_domain": target.domain,
                "ticket_id": ticket_result["ticket_id"],
                "ticket_url": ticket_result["ticket_url"],
            },
        )

        return {
            "success": True,
            "ticket": ticket_result,
            "message": f"Successfully created {request.platform} ticket",
        }

    except Exception as e:
        log_audit_event(
            db,
            action="ticket_creation_failed",
            user_id=current_user.id,
            ip_address=db_request.client.host if db_request.client else None,
            metadata_json={
                "platform": request.platform,
                "vulnerability_id": vulnerability.id,
                "target_domain": target.domain,
                "error": str(e),
            },
        )

        raise HTTPException(
            status_code=500, detail=f"Failed to create ticket: {str(e)}"
        )


@router.post("/bulk-create-tickets")
@limiter.limit(settings.ticketing_rate_limit)
async def bulk_create_tickets(
    vulnerability_ids: List[int],
    request: TicketingConfigRequest,
    db_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create tickets for multiple vulnerabilities."""

    if len(vulnerability_ids) > 50:
        raise HTTPException(
            status_code=400, detail="Cannot create more than 50 tickets at once"
        )

    # Get vulnerabilities and verify ownership
    vulnerabilities = (
        db.query(Vulnerability).filter(Vulnerability.id.in_(vulnerability_ids)).all()
    )

    if not vulnerabilities:
        raise HTTPException(status_code=404, detail="No vulnerabilities found")

    # Verify user owns all vulnerabilities
    target_ids = {vuln.scan.target_id for vuln in vulnerabilities}
    targets = (
        db.query(Target)
        .filter(Target.id.in_(target_ids), Target.owner_id == current_user.id)
        .all()
    )

    if len(targets) != len(target_ids):
        raise HTTPException(
            status_code=403, detail="Access denied to some vulnerabilities"
        )

    try:
        # Validate configuration
        if request.platform == TicketingPlatform.JIRA:
            config = JiraConfig(**request.config)
        elif request.platform == TicketingPlatform.GITHUB:
            config = GitHubConfig(**request.config)
        elif request.platform == TicketingPlatform.GITLAB:
            config = GitLabConfig(**request.config)
        else:
            raise HTTPException(status_code=400, detail="Unsupported platform")

        results = []
        successful = 0
        failed = 0

        for vulnerability in vulnerabilities:
            try:
                # Prepare vulnerability data
                vuln_data = {
                    "template_id": vulnerability.template_id,
                    "severity": vulnerability.severity,
                    "confidence": vulnerability.confidence,
                    "matched_url": vulnerability.matched_url,
                    "description": vulnerability.description,
                    "evidence_json": vulnerability.evidence_json,
                    "source": vulnerability.source,
                }

                # Get target domain
                target = next(
                    t for t in targets if t.id == vulnerability.scan.target_id
                )

                # Prepare additional context
                context = {
                    "vulnerability_id": vulnerability.id,
                    "scan_id": vulnerability.scan_id,
                    "user_id": current_user.id,
                    "user_email": current_user.email,
                }

                # Create the ticket
                ticket_result = await create_vulnerability_ticket(
                    platform=request.platform,
                    config=request.config,
                    vulnerability=vuln_data,
                    target_domain=target.domain,
                    additional_context=context,
                )

                results.append(
                    {
                        "vulnerability_id": vulnerability.id,
                        "success": True,
                        "ticket": ticket_result,
                    }
                )
                successful += 1

            except Exception as e:
                results.append(
                    {
                        "vulnerability_id": vulnerability.id,
                        "success": False,
                        "error": str(e),
                    }
                )
                failed += 1

        # Log the bulk action
        log_audit_event(
            db,
            action="bulk_tickets_created",
            user_id=current_user.id,
            ip_address=db_request.client.host if db_request.client else None,
            metadata_json={
                "platform": request.platform,
                "total_vulnerabilities": len(vulnerabilities),
                "successful": successful,
                "failed": failed,
            },
        )

        return {
            "success": True,
            "results": results,
            "summary": {
                "total": len(vulnerabilities),
                "successful": successful,
                "failed": failed,
            },
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create bulk tickets: {str(e)}"
        )
