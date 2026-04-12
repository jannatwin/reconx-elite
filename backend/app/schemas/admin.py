from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    id: int
    email: EmailStr
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: str = Field(default="user", pattern="^(user|admin)$")


class UpdateUserRequest(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = Field(None, pattern="^(user|admin)$")


class HealthStatus(BaseModel):
    status: str
    postgresql: str
    redis: str
    celery_worker: str
    timestamp: datetime


class TaskMetrics(BaseModel):
    active_scans: int
    queued_tasks: int
    completed_tasks_1h: int


class SystemMetrics(BaseModel):
    tasks: TaskMetrics
    users_total: int
    targets_total: int
    scans_total: int


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    ip_address: Optional[str]
    metadata_json: dict
    created_at: datetime

    class Config:
        from_attributes = True


class ConfigurationResponse(BaseModel):
    """Current application configuration."""

    app_name: str
    cors_allowed_origins: str
    scan_throttle_seconds: int
    nuclei_templates: str
    takeover_cname_indicators: str
    scan_nuclei_target_cap: int
    scan_header_probe_cap: int
    js_fetch_timeout_seconds: int
    js_fetch_max_assets: int
    access_token_expire_minutes: int
    refresh_token_expire_minutes: int
    
    # AI Config
    ai_scan_provider: str
    ai_scan_model: str
    ai_analyze_provider: str
    ai_analyze_model: str
    ai_report_provider: str
    ai_report_model: str
    
    # Notification Config
    slack_webhook_url: str
    discord_webhook_url: str


class UpdateConfigurationRequest(BaseModel):
    """Partial config updates - only include fields to update."""

    cors_allowed_origins: Optional[str] = None
    scan_throttle_seconds: Optional[int] = Field(None, ge=1)
    nuclei_templates: Optional[str] = None
    takeover_cname_indicators: Optional[str] = None
    scan_nuclei_target_cap: Optional[int] = Field(None, ge=1)
    scan_header_probe_cap: Optional[int] = Field(None, ge=1)
    
    # AI Config
    ai_scan_provider: Optional[str] = None
    ai_scan_model: Optional[str] = None
    ai_analyze_provider: Optional[str] = None
    ai_analyze_model: Optional[str] = None
    ai_report_provider: Optional[str] = None
    ai_report_model: Optional[str] = None
    
    # Notification Config
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
