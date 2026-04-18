from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class ManualTestLog(Base):
    """Audit trail for manual HTTP testing and payload runs (sync and background)."""

    __tablename__ = "manual_test_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type = Column(String(32), nullable=False)
    method = Column(String(16), nullable=True)
    url = Column(Text, nullable=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )
    success = Column(Boolean, nullable=False, default=False)
    status_code = Column(Integer, nullable=True)
    summary_json = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user = relationship("User", backref="manual_test_logs")
    vulnerability = relationship("Vulnerability", backref="manual_test_logs")
