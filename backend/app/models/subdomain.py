from sqlalchemy import Column, ForeignKey, Integer, String, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("scan_id", "hostname", name="uq_scan_subdomain"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    is_live = Column(Integer, default=0, nullable=False)
    ip = Column(String(45), nullable=True)  # IPv4 or IPv6
    tech_stack = Column(JSON, nullable=True)  # List of detected technologies
    cdn_waf = Column(String(255), nullable=True)  # CDN or WAF detected

    scan = relationship("Scan", back_populates="subdomains")
