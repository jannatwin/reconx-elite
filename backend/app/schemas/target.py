from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.vulnerability import VulnerabilityOut


class TargetCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=255)


class TargetUpdate(BaseModel):
    notes: str | None = Field(default=None, max_length=12000)


class SubdomainOut(BaseModel):
    id: int
    hostname: str
    is_live: bool
    environment: str = "unknown"
    tags: list[str] = Field(default_factory=list)
    takeover_candidate: bool = False
    cname: str | None = None
    ip: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    cdn: str | None = None
    waf: str | None = None
    cdn_waf: str | None = None

    class Config:
        from_attributes = True


class EndpointOut(BaseModel):
    id: int
    url: str
    hostname: str | None = None
    normalized_url: str
    path: str | None = None
    query_params: list[str] = Field(default_factory=list)
    priority_score: int = 0
    focus_reasons: list[str] = Field(default_factory=list)
    source: str = "gau"
    js_source: str | None = None
    category: str | None = None
    tags: list[str] = Field(default_factory=list)
    is_interesting: bool = False

    class Config:
        from_attributes = True



class JavaScriptAssetOut(BaseModel):
    id: int
    url: str
    normalized_url: str
    hostname: str | None = None
    source_endpoint_url: str | None = None
    status: str
    extracted_endpoints: list[str] = Field(default_factory=list)
    secrets_json: list[dict] = Field(default_factory=list)
    warnings_json: list[str] = Field(default_factory=list)
    metadata_json: dict | None = None

    class Config:
        from_attributes = True


class AttackPathOut(BaseModel):
    id: int
    title: str
    summary: str
    severity: str
    score: int
    evidence_json: dict = Field(default_factory=dict)
    steps_json: list[dict] = Field(default_factory=list)

    class Config:
        from_attributes = True


class ScanLogOut(BaseModel):
    id: int
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
    id: int
    new_subdomains: list
    new_endpoints: list
    new_vulnerabilities: list
    created_at: datetime

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    target_id: int
    status: str
    metadata_json: dict | None = None
    scan_config_json: dict | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    subdomains: list[SubdomainOut] = Field(default_factory=list)
    endpoints: list[EndpointOut] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityOut] = Field(default_factory=list)
    javascript_assets: list[JavaScriptAssetOut] = Field(default_factory=list)
    attack_paths: list[AttackPathOut] = Field(default_factory=list)
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


class ScanSummaryOut(BaseModel):
    id: int
    status: str
    metadata_json: dict | None = None
    error: str | None = None
    created_at: datetime
    subdomain_count: int = 0
    endpoint_count: int = 0
    vulnerability_count: int = 0
    high_priority_endpoint_count: int = 0


class TargetListItemOut(BaseModel):
    id: int
    domain: str
    notes: str | None = None
    created_at: datetime
    scan_count: int = 0
    latest_scan: ScanSummaryOut | None = None


ScanOut.model_rebuild()
