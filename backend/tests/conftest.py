"""Pytest configuration and fixtures for ReconX Elite tests."""

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Use in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="session")
def test_db():
    """Create test database engine."""
    engine = create_engine(
        TEST_DATABASE_URL, connect_args={"check_same_thread": False}, echo=False
    )
    return engine


@pytest.fixture(scope="function")
def test_session(test_db):
    """Create test database session."""
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_db)
    session = SessionLocal()

    yield session

    session.close()


@pytest.fixture
def mock_ai_response():
    """Mock AI model response."""
    return {
        "id": "test-123",
        "type": "analysis",
        "result": "Test analysis result",
        "confidence": 0.95,
        "model": "gemini-1.5-flash",
    }


@pytest.fixture
def mock_scan_result():
    """Mock vulnerability scan result."""
    return {
        "scan_id": "scan-123",
        "target": "example.com",
        "findings": [
            {
                "id": "vuln-001",
                "type": "sql_injection",
                "severity": "critical",
                "endpoint": "/api/users",
                "confidence": 0.92,
            },
            {
                "id": "vuln-002",
                "type": "xss_reflected",
                "severity": "high",
                "endpoint": "/search",
                "confidence": 0.85,
            },
        ],
        "total_findings": 2,
    }


@pytest.fixture
def mock_reconnaissance_result():
    """Mock reconnaissance pipeline result."""
    return {
        "phase": "reconnaissance",
        "target": "example.com",
        "subdomains": [
            {"subdomain": "api.example.com", "ip": "192.168.1.1"},
            {"subdomain": "admin.example.com", "ip": "192.168.1.2"},
        ],
        "endpoints": [
            {"url": "https://api.example.com/users", "status": 200},
            {"url": "https://api.example.com/products", "status": 200},
        ],
        "js_files": [{"url": "https://api.example.com/static/app.js", "size": 45678}],
        "total_subdomains": 2,
        "total_endpoints": 2,
    }


@pytest.fixture
def mock_session_tokens():
    """Mock session tokens."""
    return {"session_a": "token_value_a_123456", "session_b": "token_value_b_789012"}


@pytest.fixture
def mock_context_tree():
    """Mock context tree result."""
    return {
        "target": "example.com",
        "technologies": {
            "web_framework": "FastAPI",
            "database": "PostgreSQL",
            "cache": "Redis",
            "cms": None,
        },
        "endpoints": [
            {
                "path": "/api/users",
                "method": "GET",
                "parameters": ["id", "filter"],
                "auth_required": True,
            }
        ],
        "attack_surface": {
            "total_endpoints": 25,
            "authenticated_endpoints": 10,
            "public_endpoints": 15,
        },
    }
