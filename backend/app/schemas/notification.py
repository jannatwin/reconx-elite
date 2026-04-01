from datetime import datetime

from pydantic import BaseModel


class NotificationOut(BaseModel):
    id: int
    type: str
    message: str
    read: bool
    metadata_json: dict
    created_at: datetime

    class Config:
        from_attributes = True