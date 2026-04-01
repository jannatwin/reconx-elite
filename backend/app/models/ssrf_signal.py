from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class SsrfSignal(Base):
    __tablename__ = "ssrf_signals"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String(64), unique=True, nullable=False, index=True)
    payload_opportunity_id = Column(Integer, ForeignKey("payload_opportunities.id", ondelete="SET NULL"), nullable=True, index=True)

    # Detection type
    signal_type = Column(String(20), nullable=False, index=True)  # 'dns', 'http'
    target_host = Column(String(255), nullable=True)  # The host that was requested
    target_port = Column(Integer, nullable=True)  # The port that was requested

    # Request data
    ip_address = Column(String(45), nullable=False, index=True)  # IPv4/IPv6
    user_agent = Column(Text, nullable=True)
    headers_json = Column(JSON, default=dict)
    raw_request = Column(Text, nullable=True)

    # Context
    referrer = Column(String(2048), nullable=True)
    url_path = Column(String(2048), nullable=True)  # The URL where the payload was triggered
    method = Column(String(8), default="GET", nullable=False)

    # Metadata
    triggered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    processed = Column(Integer, default=0, nullable=False)  # 0=unprocessed, 1=processed, 2=ignored

    # Relationships
    user = relationship("User", back_populates="ssrf_signals")
    payload_opportunity = relationship("PayloadOpportunity", back_populates="ssrf_signals")