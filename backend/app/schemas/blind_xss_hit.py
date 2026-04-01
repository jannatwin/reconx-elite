"""Pydantic schemas for Blind XSS hits."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class BlindXssHitBase(BaseModel):
    """Base schema for blind XSS hit."""
    token: str
    payload_opportunity_id: Optional[int] = None
    ip_address: str
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    url_path: Optional[str] = None
    method: str = "GET"
    processed: int = 0


class BlindXssHitCreate(BlindXssHitBase):
    """Schema for creating a blind XSS hit."""
    pass


class BlindXssHitOut(BlindXssHitBase):
    """Schema for blind XSS hit responses."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    triggered_at: datetime
    headers_json: dict = {}
    cookies_json: dict = {}
    raw_request: Optional[str] = None


class BlindXssHitSummary(BaseModel):
    """Summary schema for blind XSS hits with related data."""
    id: int
    token: str
    ip_address: str
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    url_path: Optional[str] = None
    method: str = "GET"
    triggered_at: datetime
    processed: int = 0
    payload_opportunity: Optional[dict] = None  # Simplified payload opportunity info