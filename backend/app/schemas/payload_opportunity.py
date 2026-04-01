from datetime import datetime

from pydantic import BaseModel, Field


class PayloadOpportunityOut(BaseModel):
    """Response schema for payload testing opportunities."""

    id: int
    endpoint_id: int
    parameter_name: str
    parameter_location: str = "query"
    vulnerability_type: str
    confidence: int = Field(ge=0, le=100)
    payloads_json: list = Field(default_factory=list)
    tested_json: dict = Field(default_factory=dict)
    highest_match: str | None = None
    match_confidence: int = Field(default=0, ge=0, le=100)
    notes: str | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PayloadTestingResultOut(BaseModel):
    """Result of testing a single payload."""

    status: int
    reflected: bool
    response_snippet: str
    confidence: int = Field(ge=0, le=100)
    findings: list[str] = Field(default_factory=list)


class EndpointWithPayloadOpportunitiesOut(BaseModel):
    """Endpoint with associated payload opportunities."""

    id: int
    url: str
    normalized_url: str
    hostname: str | None = None
    priority_score: int
    source: str
    payload_opportunities: list[PayloadOpportunityOut] = Field(default_factory=list)

    class Config:
        from_attributes = True
