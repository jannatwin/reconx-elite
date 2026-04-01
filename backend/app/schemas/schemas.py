from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True


class TargetCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=255)


class VulnerabilityOut(BaseModel):
    id: int
    template_id: str | None
    severity: str | None
    matched_at: str | None
    description: str | None

    class Config:
        from_attributes = True


class SubdomainOut(BaseModel):
    id: int
    hostname: str
    is_live: bool

    class Config:
        from_attributes = True


class EndpointOut(BaseModel):
    id: int
    url: str

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    status: str
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
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
