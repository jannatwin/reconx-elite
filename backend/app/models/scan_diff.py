from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class ScanDiff(Base):
    __tablename__ = "scan_diffs"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    previous_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    new_subdomains = Column(JSON, default=list)  # List of new subdomain hostnames
    new_endpoints = Column(JSON, default=list)  # List of new endpoint URLs
    new_vulnerabilities = Column(JSON, default=list)  # List of new vuln details
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="diffs", foreign_keys=[scan_id])
    previous_scan = relationship("Scan", foreign_keys=[previous_scan_id])
