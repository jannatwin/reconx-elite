from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    String,
    func,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("owner_id", "domain", name="uq_owner_domain"),)

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain = Column(String(255), nullable=False, index=True)
    notes = Column(Text, nullable=True)
    enable_ai_processing = Column(Boolean, default=True, nullable=False)
    stealth_config = relationship(
        "StealthConfig", back_populates="target", cascade="all, delete-orphan"
    )  # Privacy control
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    scheduled_scans = relationship(
        "ScheduledScan", back_populates="target", cascade="all, delete-orphan"
    )
