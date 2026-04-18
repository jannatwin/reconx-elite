from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class CustomNucleiTemplate(Base):
    """User-defined Nuclei templates stored in database."""

    __tablename__ = "custom_nuclei_templates"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Template metadata
    name = Column(Text, nullable=False)
    author = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(Text, nullable=False)  # info, low, medium, high, critical

    # Template content
    template_content = Column(Text, nullable=False)  # YAML content
    template_type = Column(Text, nullable=False)  # file, network, workflow, etc.

    # Usage tracking
    usage_count = Column(Integer, default=0)
    successful_detections = Column(Integer, default=0)
    last_used = Column(DateTime(timezone=True), nullable=True)

    # Validation and status
    is_valid = Column(Boolean, default=False)
    validation_error = Column(Text, nullable=True)
    is_public = Column(Boolean, default=False)  # Share with community
    is_active = Column(Boolean, default=True)

    # Tags and categories
    tags = Column(Text, nullable=True)  # JSON array of tags
    category = Column(Text, nullable=True)
    cwe_ids = Column(Text, nullable=True)  # JSON array of CWE IDs

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="custom_templates")
    scan_results = relationship(
        "CustomTemplateResult", back_populates="template", cascade="all, delete-orphan"
    )


class CustomTemplateResult(Base):
    """Results from running custom Nuclei templates."""

    __tablename__ = "custom_template_results"

    id = Column(Integer, primary_key=True, index=True)
    template_id = Column(
        Integer,
        ForeignKey("custom_nuclei_templates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Match details
    matched_url = Column(Text, nullable=False)
    matched_at = Column(Text, nullable=False)
    template_id_ref = Column(Text, nullable=False)  # Template ID from match
    info_name = Column(Text, nullable=False)
    info_severity = Column(Text, nullable=False)

    # Match data
    extractors_result = Column(Text, nullable=True)  # JSON
    request = Column(Text, nullable=True)  # Request details
    response = Column(Text, nullable=True)  # Response details

    # Status
    status = Column(Text, default="found")  # found, confirmed, false_positive
    confidence = Column(Integer, default=50)  # 0-100

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    template = relationship("CustomNucleiTemplate", back_populates="scan_results")
    scan = relationship("Scan", back_populates="custom_results")
