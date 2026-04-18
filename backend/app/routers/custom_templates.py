"""API endpoints for custom Nuclei template management."""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Dict, List, Optional

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.services.custom_template_engine import template_engine
from app.services.ai_template_generator import template_generator

router = APIRouter(prefix="/templates", tags=["custom-templates"])


class TemplateGenerateDescription(BaseModel):
    """Model for generating a template from description."""

    description: str = Field(
        ..., description="Vulnerability description or requirements"
    )


class TemplateGenerateHTTP(BaseModel):
    """Model for generating a template from HTTP traffic."""

    request: str = Field(..., description="Raw HTTP request")
    response: Optional[str] = Field(None, description="Raw HTTP response")


@router.post("/generate/description")
async def generate_template_from_description(
    request: TemplateGenerateDescription, current_user: User = Depends(get_current_user)
):
    """Generate a Nuclei template from a description using AI."""

    template_yaml = await template_generator.generate_from_description(
        request.description
    )

    if not template_yaml:
        raise HTTPException(status_code=500, detail="Failed to generate template")

    return {"template_yaml": template_yaml, "source": "ai_description"}


@router.post("/generate/http")
async def generate_template_from_http(
    request: TemplateGenerateHTTP, current_user: User = Depends(get_current_user)
):
    """Generate a Nuclei template from HTTP traffic using AI."""

    template_yaml = await template_generator.generate_from_http(
        request.request, request.response
    )

    if not template_yaml:
        raise HTTPException(status_code=500, detail="Failed to generate template")

    return {"template_yaml": template_yaml, "source": "ai_http"}


class TemplateCreate(BaseModel):
    """Model for creating a custom template."""

    name: str = Field(..., description="Template name")
    template_content: str = Field(..., description="YAML template content")
    author: Optional[str] = Field(None, description="Template author")
    description: Optional[str] = Field(None, description="Template description")
    tags: Optional[List[str]] = Field(None, description="Template tags")
    is_public: bool = Field(False, description="Share template publicly")


class TemplateUpdate(BaseModel):
    """Model for updating a custom template."""

    name: Optional[str] = Field(None, description="Template name")
    description: Optional[str] = Field(None, description="Template description")
    template_content: Optional[str] = Field(None, description="YAML template content")
    tags: Optional[List[str]] = Field(None, description="Template tags")
    is_public: Optional[bool] = Field(None, description="Share template publicly")
    is_active: Optional[bool] = Field(None, description="Template active status")


class TemplateRun(BaseModel):
    """Model for running a custom template."""

    template_id: int = Field(..., description="Template ID to run")
    target_urls: List[str] = Field(..., description="Target URLs to test")


@router.post("/")
async def create_template(
    template: TemplateCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new custom Nuclei template."""

    success, message, created_template = template_engine.create_template(
        db,
        current_user.id,
        template.name,
        template.template_content,
        template.author,
        template.description,
        template.tags,
        template.is_public,
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {
        "message": message,
        "template_id": created_template.id,
        "template": {
            "id": created_template.id,
            "name": created_template.name,
            "author": created_template.author,
            "description": created_template.description,
            "severity": created_template.severity,
            "template_type": created_template.template_type,
            "tags": created_template.tags,
            "is_public": created_template.is_public,
            "is_valid": created_template.is_valid,
            "created_at": created_template.created_at,
        },
    }


@router.get("/")
async def get_templates(
    include_public: bool = True,
    only_active: bool = True,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get custom templates for the current user."""

    if search:
        templates = template_engine.search_templates(
            db, current_user.id, search, include_public
        )
    else:
        templates = template_engine.get_user_templates(
            db, current_user.id, include_public, only_active
        )

    return {
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "author": t.author,
                "description": t.description,
                "severity": t.severity,
                "template_type": t.template_type,
                "category": t.category,
                "tags": t.tags,
                "usage_count": t.usage_count,
                "successful_detections": t.successful_detections,
                "is_public": t.is_public,
                "is_valid": t.is_valid,
                "validation_error": t.validation_error,
                "is_active": t.is_active,
                "created_at": t.created_at,
                "updated_at": t.updated_at,
            }
            for t in templates
        ]
    }


@router.get("/public")
async def get_public_templates(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get public templates from all users."""

    templates = template_engine.get_public_templates(db, limit)

    return {
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "author": t.author,
                "description": t.description,
                "severity": t.severity,
                "template_type": t.template_type,
                "category": t.category,
                "tags": t.tags,
                "usage_count": t.usage_count,
                "successful_detections": t.successful_detections,
                "created_at": t.created_at,
            }
            for t in templates
        ]
    }


@router.get("/{template_id}")
async def get_template(
    template_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific template by ID."""

    templates = template_engine.get_user_templates(db, current_user.id)
    template = next((t for t in templates if t.id == template_id), None)

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    return {
        "id": template.id,
        "name": template.name,
        "author": template.author,
        "description": template.description,
        "severity": template.severity,
        "template_type": template.template_type,
        "category": template.category,
        "template_content": template.template_content,
        "tags": template.tags,
        "cwe_ids": template.cwe_ids,
        "usage_count": template.usage_count,
        "successful_detections": template.successful_detections,
        "last_used": template.last_used,
        "is_public": template.is_public,
        "is_valid": template.is_valid,
        "validation_error": template.validation_error,
        "is_active": template.is_active,
        "created_at": template.created_at,
        "updated_at": template.updated_at,
    }


@router.put("/{template_id}")
async def update_template(
    template_id: int,
    updates: TemplateUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a custom template."""

    success, message = template_engine.update_template(
        db, current_user.id, template_id, updates.dict(exclude_unset=True)
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"message": message}


@router.delete("/{template_id}")
async def delete_template(
    template_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a custom template."""

    success, message = template_engine.delete_template(db, current_user.id, template_id)

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"message": message}


@router.post("/run")
async def run_template(
    run_request: TemplateRun,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run a custom template against target URLs."""

    # Validate template ownership
    templates = template_engine.get_user_templates(db, current_user.id)
    template = next((t for t in templates if t.id == run_request.template_id), None)

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Queue template execution task
    background_tasks.add_task(
        "app.tasks.template_tasks.run_custom_template_task",
        current_user.id,
        run_request.template_id,
        run_request.target_urls,
    )

    return {
        "message": "Template execution task queued",
        "template_id": run_request.template_id,
        "target_count": len(run_request.target_urls),
    }


@router.post("/run/sync")
async def run_template_sync(
    run_request: TemplateRun,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run a custom template synchronously."""

    # Validate template ownership
    templates = template_engine.get_user_templates(db, current_user.id)
    template = next((t for t in templates if t.id == run_request.template_id), None)

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Run template
    success, message, findings = template_engine.run_template(
        db, run_request.template_id, run_request.target_urls, scan_id or 0
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {
        "success": True,
        "message": message,
        "template_id": run_request.template_id,
        "findings": findings,
        "finding_count": len(findings),
    }


@router.get("/{template_id}/results")
async def get_template_results(
    template_id: int,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get results for a specific template."""

    # Validate template ownership
    templates = template_engine.get_user_templates(db, current_user.id)
    template = next((t for t in templates if t.id == template_id), None)

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    results = template_engine.get_template_results(db, template_id, limit)

    return {
        "template_id": template_id,
        "results": [
            {
                "id": r.id,
                "matched_url": r.matched_url,
                "matched_at": r.matched_at,
                "template_id_ref": r.template_id_ref,
                "info_name": r.info_name,
                "info_severity": r.info_severity,
                "extractors_result": r.extractors_result,
                "status": r.status,
                "confidence": r.confidence,
                "created_at": r.created_at,
            }
            for r in results
        ],
    }


@router.get("/categories")
async def get_template_categories(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get available template categories."""

    templates = template_engine.get_user_templates(db, current_user.id)
    categories = list(set(t.category for t in templates if t.category))

    return {"categories": sorted(categories)}


@router.get("/statistics")
async def get_template_statistics(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get template statistics for the current user."""

    templates = template_engine.get_user_templates(db, current_user.id)

    total_templates = len(templates)
    active_templates = len([t for t in templates if t.is_active])
    valid_templates = len([t for t in templates if t.is_valid])
    public_templates = len([t for t in templates if t.is_public])

    total_usage = sum(t.usage_count for t in templates)
    total_detections = sum(t.successful_detections for t in templates)

    # Category breakdown
    category_counts = {}
    for template in templates:
        category = template.category or "other"
        category_counts[category] = category_counts.get(category, 0) + 1

    # Severity breakdown
    severity_counts = {}
    for template in templates:
        severity = template.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "total_templates": total_templates,
        "active_templates": active_templates,
        "valid_templates": valid_templates,
        "public_templates": public_templates,
        "total_usage": total_usage,
        "total_detections": total_detections,
        "category_breakdown": category_counts,
        "severity_breakdown": severity_counts,
    }
