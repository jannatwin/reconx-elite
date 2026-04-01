from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ScheduledScanCreate(BaseModel):
    target_id: int
    frequency: str  # 'daily' or 'weekly'
    scan_config: Optional[dict] = None


class ScheduledScanOut(BaseModel):
    id: int
    target_id: int
    frequency: str
    enabled: bool
    next_run: Optional[datetime]
    last_run: Optional[datetime]
    scan_config_json: dict
    created_at: datetime

    class Config:
        from_attributes = True