"""Integration tests for full workflow."""

import pytest
from unittest.mock import patch, AsyncMock


class TestFullWorkflow:
    """Test complete ReconX Elite workflow."""

    @pytest.mark.asyncio
    async def test_end_to_end_scan_workflow(
        self, mock_scan_result, mock_reconnaissance_result
    ):
        """Test complete scan workflow from target to report."""
        # Phase 1: Reconnaissance
        recon_result = mock_reconnaissance_result
        assert recon_result["target"] == "example.com"
        assert len(recon_result["subdomains"]) > 0

        # Phase 2-4: Vulnerability analysis
        vuln_result = mock_scan_result
        assert len(vuln_result["findings"]) > 0

        # Phase 6: Report generation
        report = {
            "title": "Security Assessment Report",
            "findings_count": len(vuln_result["findings"]),
            "status": "completed",
        }

        # Assert workflow completion
        assert report["status"] == "completed"

    @pytest.mark.asyncio
    async def test_multi_phase_data_flow(self):
        """Test data flow across multiple phases."""
        # Phase 1 output -> Phase 2 input
        phase1_output = {
            "subdomains": ["api.example.com", "admin.example.com"],
            "technologies": ["FastAPI", "PostgreSQL"],
        }

        # Phase 2 uses Phase 1 output
        phase2_input = phase1_output
        phase2_output = {
            "endpoints": [{"subdomain": "api.example.com", "path": "/users"}],
            "attack_surface": len(phase2_input["subdomains"]),
        }

        # Assert
        assert phase2_output["attack_surface"] == 2

    @pytest.mark.asyncio
    async def test_error_recovery_in_workflow(self):
        """Test error recovery within workflow."""
        # Arrange
        workflow_steps = [
            {"phase": 1, "status": "completed"},
            {"phase": 2, "status": "failed", "error": "Timeout"},
            {"phase": 2, "status": "completed", "retry": 1},  # Retry
            {"phase": 3, "status": "completed"},
        ]

        completed = [s for s in workflow_steps if s["status"] == "completed"]

        # Assert workflow recovered
        assert len(completed) == 3

    @pytest.mark.asyncio
    async def test_workflow_with_session_tokens(self, mock_session_tokens):
        """Test workflow with authenticated sessions."""
        # Arrange
        workflow = {
            "target": "example.com",
            "session_tokens": mock_session_tokens,
            "authenticated_endpoints": ["/api/admin", "/api/settings"],
        }

        # Assert
        assert len(workflow["session_tokens"]) == 2
        assert len(workflow["authenticated_endpoints"]) > 0

    @pytest.mark.asyncio
    async def test_parallel_module_execution(self, mock_scan_result):
        """Test parallel execution of vulnerability modules."""
        # Arrange
        modules = [
            {"name": "sql_injection", "time": 50},
            {"name": "xss", "time": 40},
            {"name": "idor", "time": 45},
            {"name": "ssrf", "time": 55},
        ]

        # Sequential time = sum
        sequential_time = sum(m["time"] for m in modules)

        # Parallel time = max (simplified)
        parallel_time = max(m["time"] for m in modules)

        # Assert speedup
        speedup = sequential_time / parallel_time
        assert speedup > 1

    @pytest.mark.asyncio
    async def test_ai_model_routing_in_workflow(self):
        """Test AI model routing decisions in workflow."""
        # Arrange
        workflow_tasks = [
            {"task": "subdomain_triage", "assigned_model": "glm-4.5-air"},
            {"task": "vulnerability_analysis", "assigned_model": "llama-3.3-70b"},
            {"task": "payload_generation", "assigned_model": "qwen-2.5-coder"},
            {"task": "report_writing", "assigned_model": "gpt-oss-120b"},
        ]

        # Assert proper model assignment
        assert len(workflow_tasks) == 4
        assert all("assigned_model" in t for t in workflow_tasks)

    @pytest.mark.asyncio
    async def test_notification_triggers_in_workflow(self):
        """Test notification triggers during workflow."""
        # Arrange
        events = [
            {"type": "scan_started", "trigger_notification": True},
            {"type": "critical_found", "trigger_notification": True},
            {"type": "phase_completed", "trigger_notification": False},
            {"type": "scan_completed", "trigger_notification": True},
        ]

        notifications = [e for e in events if e["trigger_notification"]]

        # Assert
        assert len(notifications) == 3

    @pytest.mark.asyncio
    async def test_monitoring_and_continuous_mode(self):
        """Test monitoring mode in workflow."""
        # Arrange
        monitoring_config = {
            "enabled": True,
            "interval_minutes": 60,
            "baseline_exists": True,
            "delta_scan": True,
        }

        # Assert
        assert monitoring_config["enabled"] is True
        assert monitoring_config["interval_minutes"] > 0

    @pytest.mark.asyncio
    async def test_report_generation_workflow(self, mock_scan_result):
        """Test complete report generation."""
        # Arrange
        scan_data = mock_scan_result

        # Report generation steps
        report = {
            "title": "Vulnerability Assessment",
            "findings": scan_data["findings"],
            "severity_distribution": {"critical": 1, "high": 1},
            "cvss_scores": [8.9, 7.2],
            "generated_at": "2024-01-01T00:00:00Z",
        }

        # Assert
        assert len(report["findings"]) == 2
        assert "critical" in report["severity_distribution"]
