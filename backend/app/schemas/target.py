from datetime import datetime

from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=255)


class SubdomainOut(BaseModel):
    hostname: str
    is_live: int

    class Config:
        from_attributes = True


class EndpointOut(BaseModel):
    url: str

    class Config:
        from_attributes = True


class VulnerabilityOut(BaseModel):
    template_id: str
    severity: str
    matcher_name: str | None = None
    host: str | None = None
    description: str | None = None

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    status: str
    metadata_json: dict | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    subdomains: list[SubdomainOut] = []
    endpoints: list[EndpointOut] = []
    vulnerabilities: list[VulnerabilityOut] = []

    class Config:
        from_attributes = True


class TargetOut(BaseModel):
    id: int
    domain: str
    created_at: datetime
    scans: list[ScanOut] = []

    class Config:
        from_attributes = True
