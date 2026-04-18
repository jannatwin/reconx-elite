import os
from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base, relationship
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = (
    os.getenv("DATABASE_URL")
    or f"sqlite+aiosqlite:///{os.getenv('DB_PATH', './reconx.db')}"
)

engine = create_async_engine(DATABASE_URL, future=True, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, unique=True, nullable=False, index=True)
    target = Column(String, nullable=False)
    status = Column(String, nullable=False, default="initializing")
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    total_subdomains = Column(Integer, default=0, nullable=False)
    total_live_hosts = Column(Integer, default=0, nullable=False)
    total_findings = Column(Integer, default=0, nullable=False)
    executive_summary = Column(Text, nullable=True)

    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    logs = relationship("AgentLog", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(
        String, ForeignKey("scans.session_id"), nullable=False, index=True
    )
    vuln_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    parameter = Column(String, nullable=True)
    description = Column(Text, nullable=False)
    reproduction_steps = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    status = Column(String, nullable=False, default="unconfirmed")
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan = relationship("Scan", back_populates="findings")


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(
        String, ForeignKey("scans.session_id"), nullable=False, index=True
    )
    timestamp = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    level = Column(String, nullable=False)
    model_role = Column(String, nullable=True)
    model_name = Column(String, nullable=True)
    message = Column(Text, nullable=False)
    phase = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="logs")


async def create_all_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session
