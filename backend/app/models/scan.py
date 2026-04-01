from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(50), default="pending", nullable=False, index=True)
    metadata_json = Column(JSON, default=dict)
    scan_config_json = Column(JSON, default=dict)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    target = relationship("Target", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    javascript_assets = relationship("JavaScriptAsset", back_populates="scan", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    diffs = relationship("ScanDiff", back_populates="scan", cascade="all, delete-orphan", foreign_keys="ScanDiff.scan_id")
