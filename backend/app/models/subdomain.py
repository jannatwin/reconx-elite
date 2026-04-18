from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (
        UniqueConstraint("scan_id", "hostname", name="uq_scan_subdomain"),
    )

    id = Column(Integer, primary_key=True)
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hostname = Column(String(255), nullable=False, index=True)
    is_live = Column(Boolean, default=False, nullable=False)
    environment = Column(String(32), default="unknown", nullable=False, index=True)
    tags = Column(JSON, default=list)
    takeover_candidate = Column(Boolean, default=False, nullable=False, index=True)
    cname = Column(String(512), nullable=True)
    ip = Column(String(45), nullable=True)
    tech_stack = Column(JSON, default=list)
    cdn = Column(String(255), nullable=True)
    waf = Column(String(255), nullable=True)
    cdn_waf = Column(String(255), nullable=True)

    scan = relationship("Scan", back_populates="subdomains")
