from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class BlindXssHit(Base):
    __tablename__ = "blind_xss_hits"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token = Column(String(64), unique=True, nullable=False, index=True)
    payload_opportunity_id = Column(
        Integer,
        ForeignKey("payload_opportunities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Request data
    ip_address = Column(String(45), nullable=False, index=True)  # IPv4/IPv6
    user_agent = Column(Text, nullable=True)
    headers_json = Column(JSON, default=dict)
    cookies_json = Column(JSON, default=dict)
    raw_request = Column(Text, nullable=True)

    # Context
    referrer = Column(String(2048), nullable=True)
    url_path = Column(
        String(2048), nullable=True
    )  # The URL where the payload was triggered
    method = Column(String(8), default="GET", nullable=False)

    # Metadata
    triggered_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    processed = Column(
        Integer, default=0, nullable=False
    )  # 0=unprocessed, 1=processed, 2=ignored

    # Relationships
    user = relationship("User", back_populates="blind_xss_hits")
    payload_opportunity = relationship(
        "PayloadOpportunity", back_populates="blind_xss_hits"
    )
