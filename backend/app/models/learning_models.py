from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class LearningPattern(Base):
    """Learned patterns from successful vulnerability discoveries."""

    __tablename__ = "learning_patterns"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Pattern details
    pattern_type = Column(
        Text, nullable=False
    )  # endpoint_pattern, payload_pattern, subdomain_pattern
    vulnerability_type = Column(Text, nullable=False)  # xss, sqli, ssrf, etc.
    pattern_value = Column(Text, nullable=False)  # The actual pattern
    confidence_score = Column(Integer, default=0)  # 0-100 confidence
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)

    # Context
    target_domain = Column(Text, nullable=True)
    technology_stack = Column(Text, nullable=True)  # JSON array
    discovery_method = Column(Text, nullable=True)  # nuclei, manual, ai_analysis

    # Metadata
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="learning_patterns")


class SuccessfulPayload(Base):
    """Database of successful payloads for different contexts."""

    __tablename__ = "successful_payloads"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Payload details
    payload = Column(Text, nullable=False)
    vulnerability_type = Column(Text, nullable=False)
    context = Column(Text, nullable=True)  # parameter_name, endpoint_type, etc.

    # Success metrics
    success_rate = Column(Integer, default=0)  # 0-100
    usage_count = Column(Integer, default=0)
    confirmed_vulnerabilities = Column(Integer, default=0)

    # Target information
    target_patterns = Column(
        Text, nullable=True
    )  # JSON array of URL patterns where it worked
    technology_requirements = Column(Text, nullable=True)  # JSON array of required tech

    # Metadata
    first_discovered = Column(DateTime(timezone=True), server_default=func.now())
    last_used = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="successful_payloads")


class HighValueEndpoint(Base):
    """Learned high-value endpoints based on successful discoveries."""

    __tablename__ = "high_value_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Endpoint details
    endpoint_pattern = Column(Text, nullable=False)  # Regex pattern
    endpoint_type = Column(Text, nullable=False)  # api, admin, debug, backup
    priority_score = Column(Integer, default=50)  # 0-100 priority

    # Success correlation
    vulnerabilities_found = Column(Integer, default=0)
    critical_vulnerabilities = Column(Integer, default=0)
    confirmation_rate = Column(Integer, default=0)  # 0-100

    # Context
    common_technologies = Column(Text, nullable=True)  # JSON array
    discovery_methods = Column(Text, nullable=True)  # JSON array

    # Metadata
    last_discovery = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="high_value_endpoints")
