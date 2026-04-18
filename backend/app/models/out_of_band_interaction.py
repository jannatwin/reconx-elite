from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class OutOfBandInteraction(Base):
    """Out-of-band interactions for SSRF, blind XSS, and other OAST techniques."""

    __tablename__ = "out_of_band_interactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True
    )
    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Callback details
    callback_id = Column(
        Text, nullable=False, unique=True, index=True
    )  # Unique identifier
    callback_url = Column(Text, nullable=False)  # Full callback URL
    interaction_type = Column(Text, nullable=False)  # ssrf, blind_xss, dns, etc.

    # Request details
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source_ip = Column(Text, nullable=True)
    user_agent = Column(Text, nullable=True)
    headers = Column(Text, nullable=True)  # JSON string
    body = Column(Text, nullable=True)
    method = Column(Text, nullable=True)
    path = Column(Text, nullable=True)
    query_string = Column(Text, nullable=True)

    # Analysis
    is_confirmed = Column(Boolean, default=False)
    confidence_score = Column(Text, default="low")  # low, medium, high
    analysis_notes = Column(Text, nullable=True)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="oob_interactions")
    scan = relationship("Scan", back_populates="oob_interactions")
    vulnerability = relationship("Vulnerability", back_populates="oob_interactions")
