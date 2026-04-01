from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class JavaScriptAsset(Base):
    __tablename__ = "javascript_assets"
    __table_args__ = (UniqueConstraint("scan_id", "normalized_url", name="uq_scan_js_asset"),)

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    normalized_url = Column(String(2048), nullable=False, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    source_endpoint_url = Column(String(2048), nullable=True)
    status = Column(String(32), default="queued", nullable=False, index=True)
    extracted_endpoints = Column(JSON, default=list)
    secrets_json = Column(JSON, default=list)
    warnings_json = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    content_sha256 = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    scan = relationship("Scan", back_populates="javascript_assets")
