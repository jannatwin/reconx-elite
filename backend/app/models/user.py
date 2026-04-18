from sqlalchemy import Column, DateTime, Integer, String, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    targets = relationship(
        "Target", back_populates="owner", cascade="all, delete-orphan"
    )
    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs = relationship("AuditLog", back_populates="user")
    scheduled_scans = relationship(
        "ScheduledScan", back_populates="user", cascade="all, delete-orphan"
    )
    notifications = relationship(
        "Notification", back_populates="user", cascade="all, delete-orphan"
    )
    bookmarks = relationship(
        "Bookmark", back_populates="user", cascade="all, delete-orphan"
    )
    blind_xss_hits = relationship(
        "BlindXssHit", back_populates="user", cascade="all, delete-orphan"
    )
    ssrf_signals = relationship(
        "SsrfSignal", back_populates="user", cascade="all, delete-orphan"
    )
    oob_interactions = relationship(
        "OutOfBandInteraction", back_populates="user", cascade="all, delete-orphan"
    )
    learning_patterns = relationship(
        "LearningPattern", back_populates="user", cascade="all, delete-orphan"
    )
    successful_payloads = relationship(
        "SuccessfulPayload", back_populates="user", cascade="all, delete-orphan"
    )
    high_value_endpoints = relationship(
        "HighValueEndpoint", back_populates="user", cascade="all, delete-orphan"
    )
    custom_templates = relationship(
        "CustomNucleiTemplate", back_populates="user", cascade="all, delete-orphan"
    )
    smart_wordlists = relationship(
        "SmartWordlist", back_populates="user", cascade="all, delete-orphan"
    )
