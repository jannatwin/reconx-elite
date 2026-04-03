from datetime import datetime, timezone

import redis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import require_admin
from app.core.security import hash_password
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.admin import (
    AuditLogResponse,
    ConfigurationResponse,
    CreateUserRequest,
    HealthStatus,
    SystemMetrics,
    TaskMetrics,
    UpdateConfigurationRequest,
    UpdateUserRequest,
    UserListResponse,
    UserResponse,
)
from app.services.audit import log_audit_event

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserListResponse])
def list_users(
    skip: int = 0,
    limit: int = 100,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List all users in the system. Admin only."""
    users = db.query(User).offset(skip).limit(limit).all()
    return users


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a new user account. Admin only."""
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db,
        action="admin_user_created",
        user_id=admin.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"created_user_email": payload.email, "created_user_role": payload.role},
    )

    return user


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Retrieve a specific user's details. Admin only."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Update a user's details (email, role). Admin only."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.email and payload.email != user.email:
        existing = db.query(User).filter(User.email == payload.email).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        user.email = payload.email

    old_role = user.role
    if payload.role:
        user.role = payload.role

    db.commit()
    db.refresh(user)

    log_audit_event(
        db,
        action="admin_user_updated",
        user_id=admin.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={
            "updated_user_id": user_id,
            "old_role": old_role,
            "new_role": user.role,
        },
    )

    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Delete a user account and cascade delete associated data. Admin only."""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    email = user.email
    db.delete(user)
    db.commit()

    log_audit_event(
        db,
        action="admin_user_deleted",
        user_id=admin.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"deleted_user_email": email},
    )


@router.get("/health", response_model=HealthStatus)
def system_health(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Check system health status of all critical services. Admin only."""
    health = {
        "status": "unknown",
        "postgresql": "unknown",
        "redis": "unknown",
        "celery_worker": "unknown",
        "timestamp": datetime.now(timezone.utc),
    }

    # Check PostgreSQL
    try:
        db.execute("SELECT 1")
        health["postgresql"] = "healthy"
    except Exception:
        health["postgresql"] = "unhealthy"

    # Check Redis
    try:
        r = redis.from_url(settings.redis_url)
        r.ping()
        health["redis"] = "healthy"
    except Exception:
        health["redis"] = "unhealthy"

    # Check Celery worker (check if there are active tasks)
    try:
        from app.tasks.celery_app import celery_app

        inspect = celery_app.control.inspect()
        stats = inspect.stats()
        health["celery_worker"] = "healthy" if stats else "unhealthy"
    except Exception:
        health["celery_worker"] = "unhealthy"

    # Overall status
    if all(v != "unhealthy" for k, v in health.items() if k != "status" and k != "timestamp"):
        health["status"] = "healthy"
    elif any(v == "unhealthy" for k, v in health.items() if k != "status" and k != "timestamp"):
        health["status"] = "degraded"

    return health


@router.get("/metrics", response_model=SystemMetrics)
def system_metrics(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Retrieve system-wide metrics. Admin only."""
    from app.tasks.celery_app import celery_app

    # Count tasks
    try:
        inspect = celery_app.control.inspect()
        active = inspect.active() or {}
        reserved = inspect.reserved() or {}
        active_scans = sum(len(v) for v in active.values())
        queued_tasks = sum(len(v) for v in reserved.values())
    except Exception:
        active_scans = 0
        queued_tasks = 0

    # Count completed tasks in last hour (approximate via recent scans)
    one_hour_ago = datetime.now(timezone.utc)
    recent_scans = db.query(Scan).filter(Scan.created_at >= one_hour_ago).count()
    completed_tasks_1h = recent_scans

    users_total = db.query(User).count()
    targets_total = db.query(Target).count()
    scans_total = db.query(Scan).count()

    return SystemMetrics(
        tasks=TaskMetrics(
            active_scans=active_scans,
            queued_tasks=queued_tasks,
            completed_tasks_1h=completed_tasks_1h,
        ),
        users_total=users_total,
        targets_total=targets_total,
        scans_total=scans_total,
    )


@router.get("/audit-logs", response_model=list[AuditLogResponse])
def list_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action_filter: str = None,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Retrieve audit logs. Admin only."""
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())

    if action_filter:
        query = query.filter(AuditLog.action.contains(action_filter))

    logs = query.offset(skip).limit(limit).all()
    return logs


@router.get("/config", response_model=ConfigurationResponse)
def get_configuration(admin: User = Depends(require_admin)):
    """Get current application configuration. Admin only."""
    return ConfigurationResponse(
        app_name=settings.app_name,
        cors_allowed_origins=settings.cors_allowed_origins,
        scan_throttle_seconds=settings.scan_throttle_seconds,
        nuclei_templates=settings.nuclei_templates,
        takeover_cname_indicators=settings.takeover_cname_indicators,
        scan_nuclei_target_cap=settings.scan_nuclei_target_cap,
        scan_header_probe_cap=settings.scan_header_probe_cap,
        js_fetch_timeout_seconds=settings.js_fetch_timeout_seconds,
        js_fetch_max_assets=settings.js_fetch_max_assets,
        access_token_expire_minutes=settings.access_token_expire_minutes,
        refresh_token_expire_minutes=settings.refresh_token_expire_minutes,
    )


@router.put("/config", response_model=ConfigurationResponse)
def update_configuration(
    payload: UpdateConfigurationRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Update application configuration. Admin only.
    NOTE: This updates settings in memory. For persistent changes, update .env and restart app.
    """
    changes = {}

    if payload.cors_allowed_origins:
        changes["cors_allowed_origins"] = settings.cors_allowed_origins
        settings.cors_allowed_origins = payload.cors_allowed_origins

    if payload.scan_throttle_seconds:
        changes["scan_throttle_seconds"] = settings.scan_throttle_seconds
        settings.scan_throttle_seconds = payload.scan_throttle_seconds

    if payload.nuclei_templates:
        changes["nuclei_templates"] = settings.nuclei_templates
        settings.nuclei_templates = payload.nuclei_templates

    if payload.takeover_cname_indicators:
        changes["takeover_cname_indicators"] = settings.takeover_cname_indicators
        settings.takeover_cname_indicators = payload.takeover_cname_indicators

    if payload.scan_nuclei_target_cap:
        changes["scan_nuclei_target_cap"] = settings.scan_nuclei_target_cap
        settings.scan_nuclei_target_cap = payload.scan_nuclei_target_cap

    if payload.scan_header_probe_cap:
        changes["scan_header_probe_cap"] = settings.scan_header_probe_cap
        settings.scan_header_probe_cap = payload.scan_header_probe_cap

    log_audit_event(
        db,
        action="admin_config_updated",
        user_id=admin.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"changes": changes},
    )

    return ConfigurationResponse(
        app_name=settings.app_name,
        cors_allowed_origins=settings.cors_allowed_origins,
        scan_throttle_seconds=settings.scan_throttle_seconds,
        nuclei_templates=settings.nuclei_templates,
        takeover_cname_indicators=settings.takeover_cname_indicators,
        scan_nuclei_target_cap=settings.scan_nuclei_target_cap,
        scan_header_probe_cap=settings.scan_header_probe_cap,
        js_fetch_timeout_seconds=settings.js_fetch_timeout_seconds,
        js_fetch_max_assets=settings.js_fetch_max_assets,
        access_token_expire_minutes=settings.access_token_expire_minutes,
        refresh_token_expire_minutes=settings.refresh_token_expire_minutes,
    )
