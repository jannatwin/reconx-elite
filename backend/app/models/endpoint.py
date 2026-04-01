from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, JSON, UniqueConstraint
from sqlalchemy.orm import relationship

from app.core.database import Base


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_scan_endpoint"),)

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False, index=True)
    category = Column(String(50), nullable=True)  # API, login, admin, static
    tags = Column(JSON, nullable=True)  # List of tags
    is_interesting = Column(Boolean, default=False, nullable=False)

    scan = relationship("Scan", back_populates="endpoints")
    bookmarks = relationship("Bookmark", back_populates="endpoint", cascade="all, delete-orphan")
