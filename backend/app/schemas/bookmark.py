from datetime import datetime

from pydantic import BaseModel


class BookmarkCreate(BaseModel):
    endpoint_id: int
    note: str | None = None


class BookmarkOut(BaseModel):
    id: int
    endpoint_id: int
    note: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True