from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    module = Column(String(64), nullable=False)
    tool = Column(String(64), nullable=False)
    format_ = Column("format", String(32), nullable=False, default="text")
    summary_json = Column(JSON, default=dict)
    text_preview = Column(Text, nullable=True)
    blob_path = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="artifacts")
