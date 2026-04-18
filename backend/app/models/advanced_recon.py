from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import relationship

from app.core.database import Base


class StealthConfig(Base):
    """Stealth scanning configuration per target."""

    __tablename__ = "stealth_configs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Scan mode configuration
    scan_mode = Column(
        Text, nullable=False, default="balanced"
    )  # aggressive, balanced, stealth

    # Rate limiting
    requests_per_second = Column(Integer, default=5)
    random_delay_min = Column(Integer, default=100)  # milliseconds
    random_delay_max = Column(Integer, default=500)  # milliseconds

    # Concurrency
    concurrent_threads = Column(Integer, default=2)
    max_retries = Column(Integer, default=3)
    retry_backoff_factor = Column(Integer, default=2)

    # User agent rotation
    rotate_user_agents = Column(Boolean, default=True)
    custom_user_agents = Column(Text, nullable=True)  # JSON array

    # Advanced stealth options
    use_jitter = Column(Boolean, default=True)
    jitter_percentage = Column(Integer, default=20)  # 20% jitter
    respect_robots_txt = Column(Boolean, default=True)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    target = relationship("Target", back_populates="stealth_config")


class DiscoveredParameter(Base):
    """Discovered parameters during advanced recon."""

    __tablename__ = "discovered_parameters"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id = Column(
        Integer,
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Parameter details
    parameter_name = Column(Text, nullable=False)
    parameter_type = Column(Text, nullable=False)  # query, post, header, cookie
    parameter_value = Column(Text, nullable=True)  # discovered value if any

    # Discovery metadata
    discovery_method = Column(
        Text, nullable=False
    )  # fuzzing, parameter_bruteforce, analysis
    confidence_score = Column(Integer, default=50)  # 0-100
    response_indicators = Column(Text, nullable=True)  # JSON array of indicators

    # Response analysis
    status_code_change = Column(Integer, nullable=True)
    response_length_change = Column(Integer, nullable=True)
    reflection_detected = Column(Boolean, default=False)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="discovered_parameters")
    endpoint = relationship("Endpoint", back_populates="discovered_parameters")


class FuzzedEndpoint(Base):
    """Discovered endpoints during fuzzing."""

    __tablename__ = "fuzzed_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Endpoint details
    url = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    method = Column(Text, nullable=False, default="GET")

    # Response details
    status_code = Column(Integer, nullable=False)
    response_length = Column(Integer, nullable=False)
    response_time_ms = Column(Integer, nullable=True)

    # Analysis
    is_interesting = Column(Boolean, default=False)
    interest_reasons = Column(Text, nullable=True)  # JSON array of reasons
    content_type = Column(Text, nullable=True)
    server_header = Column(Text, nullable=True)

    # Fuzzing metadata
    wordlist_used = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)  # The word that worked

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="fuzzed_endpoints")


class SmartWordlist(Base):
    """Smart wordlists with categorization and success tracking."""

    __tablename__ = "smart_wordlists"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Wordlist details
    name = Column(Text, nullable=False)
    category = Column(Text, nullable=False)  # endpoints, parameters, admin, api, etc.
    description = Column(Text, nullable=True)

    # Wordlist content
    words = Column(Text, nullable=False)  # JSON array of words
    word_count = Column(Integer, nullable=False)

    # Usage statistics
    usage_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    success_rate = Column(Integer, default=0)  # 0-100

    # Prioritization
    priority_score = Column(Integer, default=50)  # 0-100
    is_active = Column(Boolean, default=True)
    is_public = Column(Boolean, default=False)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="smart_wordlists")
