from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class PayloadOpportunity(Base):
    __tablename__ = "payload_opportunities"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(
        Integer,
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parameter_name = Column(String(255), nullable=False)
    parameter_location = Column(
        String(32), nullable=False, default="query"
    )  # query, body, path, header
    vulnerability_type = Column(
        String(50), nullable=False, index=True
    )  # xss, sqli, ssti, ssrf, openredirect
    confidence = Column(Integer, default=50, nullable=False)  # 0-100 confidence score
    payloads_json = Column(JSON, default=list)  # list of payload strings to test
    tested_json = Column(
        JSON, default=dict
    )  # {payload: {status: int, reflected: bool, response_snippet: str}}
    highest_match = Column(String(50), nullable=True)  # highest confidence detection
    match_confidence = Column(Integer, default=0, nullable=False)  # 0-100
    notes = Column(String(1024), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), onupdate=func.now(), server_default=func.now()
    )

    endpoint = relationship("Endpoint", back_populates="payload_opportunities")
    scan = relationship("Scan", back_populates="payload_opportunities")
    blind_xss_hits = relationship(
        "BlindXssHit",
        back_populates="payload_opportunity",
        cascade="all, delete-orphan",
    )
    ssrf_signals = relationship(
        "SsrfSignal", back_populates="payload_opportunity", cascade="all, delete-orphan"
    )
