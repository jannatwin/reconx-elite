from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    severity = Column(String(32), default="medium", nullable=False, index=True)
    score = Column(Integer, default=0, nullable=False, index=True)
    evidence_json = Column(JSON, default=dict)
    steps_json = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="attack_paths")
