import re
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, field_validator

DOMAIN_PATTERN = re.compile(r"^(?!-)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$")


class ScanRequest(BaseModel):
    target: str

    @field_validator('target')
    @classmethod
    def normalize_target(cls, value: str) -> str:
        value = value.strip().lower()
        value = re.sub(r'^https?://', '', value)
        value = re.sub(r'^www\.', '', value)
        if len(value) > 253:
            raise ValueError('Domain name too long (max 253 characters per RFC 1035)')
        if not DOMAIN_PATTERN.fullmatch(value):
            raise ValueError('Invalid domain format')
        return value


class ScanSession(BaseModel):
    session_id: str
    target: str
    status: str
    phases_completed: List[str]
    phases_pending: List[str]
    current_phase: str
    stats: Dict[str, int]


class Finding(BaseModel):
    id: Optional[int] = None
    session_id: str
    vuln_type: str
    severity: str
    endpoint: str
    parameter: Optional[str] = None
    description: str
    reproduction_steps: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    status: str


class AgentLog(BaseModel):
    session_id: str
    level: str
    model_role: Optional[str] = None
    model_name: Optional[str] = None
    message: str
    phase: Optional[str] = None
    timestamp: Optional[str] = None


class WebSocketMessage(BaseModel):
    type: str
    data: Dict[str, object]
    session_id: str
    timestamp: str


class AIModelConfig(BaseModel):
    role: str
    model_id: str
    description: str
