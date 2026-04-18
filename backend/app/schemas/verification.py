from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, RootModel


class AgentLogEventOut(BaseModel):
    type: str | None = None
    event: str | None = None
    timestamp: str
    role: str | None = None
    model_id: str | None = None
    task: str | None = None
    status: str | None = None
    success: bool | None = None
    tokens_used: int | None = None
    message: str | None = None
    error: str | None = None
    origin_process: str | None = None


class HostGroupState(BaseModel):
    total_discovered: int = 0
    live: int = 0
    auth_targets: list[str] = Field(default_factory=list)
    api_targets: list[str] = Field(default_factory=list)
    admin_targets: list[str] = Field(default_factory=list)
    dev_targets: list[str] = Field(default_factory=list)
    skip: list[str] = Field(default_factory=list)


class JavaScriptAnalysisState(BaseModel):
    files_analyzed: int = 0
    endpoints_found: list[str] = Field(default_factory=list)
    secrets_found: list[dict[str, Any]] = Field(default_factory=list)
    escalate_immediately: bool = False


class VerificationFinding(BaseModel):
    id: str
    type: str
    endpoint: str
    parameter: str = ""
    payload_used: str = ""
    severity: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    reproduction_steps: list[str] = Field(default_factory=list)
    raw_request: str = ""
    impact: str = ""
    remediation: str = ""
    chain_with: list[str] = Field(default_factory=list)
    status: str = "unconfirmed"
    details: dict[str, Any] = Field(default_factory=dict)


class VerificationState(BaseModel):
    session_id: str
    target: str
    wildcard: str
    scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    scan_mode: str = "passive"
    current_phase: str = "recon"
    hosts: HostGroupState = Field(default_factory=HostGroupState)
    js_analysis: JavaScriptAnalysisState = Field(
        default_factory=JavaScriptAnalysisState
    )
    findings: list[VerificationFinding] = Field(default_factory=list)
    chains_identified: list[dict[str, Any]] = Field(default_factory=list)
    reports_drafted: int = 0
    model_call_log: list[AgentLogEventOut] = Field(default_factory=list)
    next_action: str = ""
    blockers: list[str] = Field(default_factory=list)
    escalations: list[str] = Field(default_factory=list)


class HostTriageRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    target_id: int | None = None


class HostTriageRecord(BaseModel):
    host: str
    classification: str
    reason: str


class HostTriageResponse(BaseModel):
    classifications: list[HostTriageRecord] = Field(default_factory=list)


class JavaScriptAnalysisRequest(BaseModel):
    js_content: str
    source_url: str | None = None
    target_id: int | None = None


class JavaScriptAnalysisResponse(BaseModel):
    source_url: str | None = None
    endpoints_found: list[str] = Field(default_factory=list)
    secrets_found: list[dict[str, Any]] = Field(default_factory=list)
    internal_urls: list[str] = Field(default_factory=list)
    auth_logic: bool = False
    escalate_immediately: bool = False


class PayloadGenerationRequest(BaseModel):
    vuln_type: str
    context: dict[str, Any] = Field(default_factory=dict)
    target_id: int | None = None


class PayloadGenerationResponse(BaseModel):
    vuln_type: str
    payloads: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    sqlmap_command: str | None = None


class SeverityRequest(BaseModel):
    finding: dict[str, Any]
    target_id: int | None = None


class SeverityResponse(BaseModel):
    score: float
    vector: str
    label: str
    justification: str


class ChainAnalysisRequest(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list)
    target_id: int | None = None


class ChainAnalysisResponse(BaseModel):
    chains: list[dict[str, Any]] = Field(default_factory=list)


class ReportWriteRequest(BaseModel):
    finding: dict[str, Any]
    severity: str | None = None
    target_id: int | None = None


class ReportWriteResponse(BaseModel):
    report: dict[str, Any]


class FindingsResponse(BaseModel):
    findings: list[VerificationFinding] = Field(default_factory=list)


class AgentLogHistoryResponse(BaseModel):
    events: list[AgentLogEventOut] = Field(default_factory=list)


class ModelVerificationEntry(BaseModel):
    model: str
    status: str
    response: str | None = None
    error: str | None = None
    last_verified_at: str | None = None
    calls_made: int | None = None


class ModelStatusResponse(BaseModel):
    provider: str
    models: dict[str, str]
    statuses: dict[str, ModelVerificationEntry]
    updated_at: str | None = None


class ModelVerificationResponse(RootModel[dict[str, ModelVerificationEntry]]):
    pass
