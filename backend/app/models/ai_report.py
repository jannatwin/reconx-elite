from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class AIReport(Base):
    """AI-generated vulnerability reports with enhanced security and metadata."""
    
    __tablename__ = "ai_reports"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Report content
    title = Column(Text, nullable=False)
    summary = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)  # low, medium, high, critical
    confidence_score = Column(Text, nullable=False, default="medium")  # low, medium, high
    
    # Technical details
    cwe_mapping = Column(Text, nullable=True)  # JSON array of CWE IDs
    owasp_mapping = Column(Text, nullable=True)  # JSON array of OWASP Top 10 categories
    cvss_score = Column(Text, nullable=True)  # CVSS estimation
    technical_details = Column(Text, nullable=True)  # Request/response details
    proof_of_concept = Column(Text, nullable=True)  # Reproducible commands
    exploit_draft = Column(Text, nullable=True)  # AI-generated exploit draft/PoC
    
    # Impact and remediation
    business_impact = Column(Text, nullable=True)
    bounty_estimate = Column(Text, nullable=True)
    remediation_steps = Column(Text, nullable=True)
    
    # Metadata
    ai_model_version = Column(Text, nullable=True)  # Gemini model used
    processing_time_ms = Column(Integer, nullable=True)
    data_sent_hash = Column(Text, nullable=True)  # Hash of data sent to AI (for audit)
    is_ai_assisted = Column(Boolean, default=True, nullable=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="ai_report")
