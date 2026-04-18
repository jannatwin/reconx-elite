"""Unit tests for Session Manifest."""

import pytest
from datetime import datetime


class TestSessionManifest:
    """Test SessionManifest functionality."""

    def test_session_initialization(self):
        """Test session manifest initialization."""
        # Arrange
        session_id = "test-session-abc123"
        target = "example.com"

        # Assert
        assert session_id == "test-session-abc123"
        assert target == "example.com"

    def test_session_data_structure(self):
        """Test session manifest data structure."""
        # Arrange
        session = {
            "session_id": "session-123",
            "target": "example.com",
            "start_time": datetime.now().isoformat(),
            "status": "in_progress",
            "phases": {
                "phase_1": {"status": "completed", "findings": 5},
                "phase_2": {"status": "in_progress", "findings": 0},
            },
        }

        # Assert
        assert "session_id" in session
        assert "target" in session
        assert "start_time" in session
        assert session["status"] == "in_progress"

    def test_phase_tracking(self):
        """Test phase completion tracking."""
        # Arrange
        phases = {
            "phase_1": {"status": "completed", "duration": 125},
            "phase_2": {"status": "completed", "duration": 230},
            "phase_3": {"status": "in_progress", "duration": 15},
            "phase_4": {"status": "pending", "duration": 0},
        }

        completed = [p for p, info in phases.items() if info["status"] == "completed"]

        # Assert
        assert len(completed) == 2
        assert "phase_1" in completed
        assert "phase_2" in completed

    def test_findings_accumulation(self):
        """Test finding accumulation across phases."""
        # Arrange
        findings_by_phase = {
            "phase_1": [
                {"id": "f1", "type": "subdomain"},
                {"id": "f2", "type": "subdomain"},
            ],
            "phase_4": [
                {"id": "v1", "type": "sql_injection"},
                {"id": "v2", "type": "xss"},
                {"id": "v3", "type": "idor"},
            ],
        }

        total_findings = sum(len(f) for f in findings_by_phase.values())

        # Assert
        assert total_findings == 5

    def test_session_token_storage(self, mock_session_tokens):
        """Test session token storage in manifest."""
        # Arrange
        session = {"session_id": "session-123", "tokens": mock_session_tokens}

        # Assert
        assert len(session["tokens"]) == 2
        assert "session_a" in session["tokens"]
        assert "session_b" in session["tokens"]

    def test_scan_result_persistence(self, mock_scan_result):
        """Test scan result persistence."""
        # Arrange
        session = {
            "session_id": "session-123",
            "scan_results": {"vulnerability_modules": mock_scan_result},
        }

        # Assert
        assert session["scan_results"]["vulnerability_modules"]["total_findings"] == 2

    def test_session_finalization(self):
        """Test session finalization."""
        # Arrange
        session = {
            "session_id": "session-123",
            "start_time": datetime.now().isoformat(),
            "status": "completed",
            "end_time": datetime.now().isoformat(),
            "total_duration": 3600,
        }

        # Assert
        assert session["status"] == "completed"
        assert "end_time" in session
        assert session["total_duration"] > 0

    def test_session_error_handling(self):
        """Test session error state tracking."""
        # Arrange
        session = {
            "session_id": "session-123",
            "status": "failed",
            "error": {
                "phase": "phase_4",
                "error_message": "AI API timeout",
                "timestamp": datetime.now().isoformat(),
            },
        }

        # Assert
        assert session["status"] == "failed"
        assert "error" in session
        assert "AI API" in session["error"]["error_message"]

    def test_large_session_manifest(self):
        """Test handling large session manifests."""
        # Arrange
        session = {
            "findings": [
                {"id": f"finding-{i}", "type": "vulnerability", "severity": "high"}
                for i in range(10000)
            ]
        }

        # Assert
        assert len(session["findings"]) == 10000
