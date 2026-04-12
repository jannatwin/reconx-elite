from pydantic import BaseModel
from datetime import datetime

class AIReportOut(BaseModel):
    id: int
    vulnerability_id: int
    title: str
    summary: str
    severity: str
    confidence_score: str
    cwe_mapping: str | None = None
    owasp_mapping: str | None = None
    cvss_score: str | None = None
    technical_details: str | None = None
    proof_of_concept: str | None = None
    exploit_draft: str | None = None
    business_impact: str | None = None
    bounty_estimate: str | None = None
    remediation_steps: str | None = None
    ai_model_version: str | None = None
    processing_time_ms: int | None = None
    created_at: datetime

    class Config:
        from_attributes = True
