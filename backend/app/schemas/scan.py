from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

TemplateCategory = Literal["cves", "exposures", "misconfiguration", "fuzzing"]
SeverityLevel = Literal["low", "medium", "high", "critical"]


class ScanConfigRequest(BaseModel):
    selected_templates: list[TemplateCategory] = Field(default_factory=list)
    severity_filter: list[SeverityLevel] = Field(default_factory=list)


class ScanLogSummary(BaseModel):
    id: int
    step: str
    status: str
    started_at: datetime
    ended_at: datetime
    duration_ms: int
    attempts: int
    details_json: dict | None = None

    class Config:
        from_attributes = True


class ScanStatusOut(BaseModel):
    id: int
    target_id: int
    status: str
    metadata_json: dict | None = None
    scan_config_json: dict | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    logs: list[ScanLogSummary] = Field(default_factory=list)

    class Config:
        from_attributes = True
