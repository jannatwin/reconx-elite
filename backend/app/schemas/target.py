from datetime import datetime

from pydantic import BaseModel, Field, Field


class TargetCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=255)


class SubdomainOut(BaseModel):
    hostname: str
    is_live: int
    ip: str | None = None
    tech_stack: list | None = None
    cdn_waf: str | None = None

    class Config:
        from_attributes = True


class EndpointOut(BaseModel):
    url: str
    category: str | None = None
    tags: list | None = None
    is_interesting: bool = False

    class Config:
        from_attributes = True


class VulnerabilityOut(BaseModel):
    template_id: str
    severity: str
    matcher_name: str | None = None
    matched_url: str | None = None
    host: str | None = None
    description: str | None = None
    notes: str | None = None

    class Config:
        from_attributes = True


class ScanLogOut(BaseModel):
    step: str
    status: str
    started_at: datetime
    ended_at: datetime
    duration_ms: int
    attempts: int
    stdout: str | None = None
    stderr: str | None = None
    details_json: dict | None = None

    class Config:
        from_attributes = True


class ScanDiffOut(BaseModel):
    new_subdomains: list
    new_endpoints: list
    new_vulnerabilities: list
    created_at: datetime

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    status: str
    metadata_json: dict | None = None
    scan_config_json: dict | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    subdomains: list[SubdomainOut] = Field(default_factory=list)
    endpoints: list[EndpointOut] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityOut] = Field(default_factory=list)
    logs: list["ScanLogOut"] = Field(default_factory=list)
    diffs: list[ScanDiffOut] = Field(default_factory=list)

    class Config:
        from_attributes = True


class TargetOut(BaseModel):
    id: int
    domain: str
    notes: str | None = None
    created_at: datetime
    scans: list[ScanOut] = Field(default_factory=list)

    class Config:
        from_attributes = True
