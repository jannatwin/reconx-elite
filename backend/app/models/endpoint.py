from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, JSON, UniqueConstraint
from sqlalchemy.orm import relationship

from app.core.database import Base


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("scan_id", "normalized_url", name="uq_scan_endpoint_normalized"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    normalized_url = Column(String(2048), nullable=False, index=True)
    path = Column(String(2048), nullable=True)
    query_params = Column(JSON, default=list)
    priority_score = Column(Integer, default=0, nullable=False, index=True)
    focus_reasons = Column(JSON, default=list)
    source = Column(String(16), default="gau", nullable=False, index=True)
    js_source = Column(String(2048), nullable=True)
    category = Column(String(50), nullable=True)
    tags = Column(JSON, default=list)
    is_interesting = Column(Boolean, default=False, nullable=False)

    scan = relationship("Scan", back_populates="endpoints")
    bookmarks = relationship("Bookmark", back_populates="endpoint", cascade="all, delete-orphan")
