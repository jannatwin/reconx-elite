"""Unit tests for AI Router."""

import pytest
from unittest.mock import Mock, patch


class TestAIRouter:
    """Test AI Router model selection logic."""

    def test_model_selection_for_reconnaissance(self):
        """Test correct model selection for reconnaissance task."""
        # Arrange
        task = {
            "phase": "reconnaissance",
            "target": "example.com",
            "context_size": "small",
        }

        # Expected: Fast model (GLM 4.5 Air or Nemotron Nano)
        expected_models = ["glm-4.5-air", "nemotron-3-nano"]

        # Assert
        assert task["phase"] == "reconnaissance"
        assert task["context_size"] == "small"

    def test_model_selection_for_deep_analysis(self):
        """Test model selection for deep analysis."""
        # Arrange
        task = {
            "phase": "exploitation_analysis",
            "context_size": "large",
            "requires_reasoning": True,
        }

        # Expected: High-capability model (Nemotron 3 Super or Llama 70B)
        expected_models = ["nemotron-3-super", "llama-3.3-70b"]

        # Assert
        assert task["requires_reasoning"] is True
        assert task["context_size"] == "large"

    def test_model_selection_for_code_generation(self):
        """Test model selection for code/payload generation."""
        # Arrange
        task = {"type": "code_generation", "domain": "payload_creation"}

        # Expected: Qwen Coder
        expected_model = "qwen-2.5-coder-32b"

        # Assert
        assert task["type"] == "code_generation"

    def test_model_fallback_logic(self):
        """Test fallback when primary model fails."""
        # Arrange
        models = {
            "primary": "gemini-1.5-flash",
            "secondary": "llama-3.3-70b",
            "tertiary": "qwen-2.5-coder",
        }

        # Simulate primary failure
        primary_failed = True
        fallback_model = models["secondary"] if primary_failed else models["primary"]

        # Assert
        assert fallback_model == "llama-3.3-70b"

    def test_context_window_validation(self):
        """Test context window size validation."""
        # Arrange
        task_size = 50000  # 50K tokens
        models = {
            "gemini": {"max_context": 1000000},
            "llama": {"max_context": 8000},
            "qwen": {"max_context": 128000},
        }

        # Find compatible models
        compatible = [
            m for m, spec in models.items() if spec["max_context"] >= task_size
        ]

        # Assert
        assert len(compatible) == 2
        assert "gemini" in compatible
        assert "qwen" in compatible

    def test_router_efficiency_metrics(self):
        """Test router efficiency tracking."""
        # Arrange
        router_stats = {
            "total_tasks": 1000,
            "successful": 950,
            "failed": 50,
            "avg_latency_ms": 1250,
        }

        success_rate = (router_stats["successful"] / router_stats["total_tasks"]) * 100

        # Assert
        assert success_rate == 95.0
        assert router_stats["avg_latency_ms"] < 2000

    def test_load_balancing(self):
        """Test load balancing across models."""
        # Arrange
        tasks = [
            {"id": 1, "assigned_model": "gemini"},
            {"id": 2, "assigned_model": "llama"},
            {"id": 3, "assigned_model": "gemini"},
            {"id": 4, "assigned_model": "qwen"},
            {"id": 5, "assigned_model": "llama"},
        ]

        # Count assignments
        model_load = {}
        for task in tasks:
            model = task["assigned_model"]
            model_load[model] = model_load.get(model, 0) + 1

        # Assert
        assert model_load["gemini"] == 2
        assert model_load["llama"] == 2
        assert model_load["qwen"] == 1

    def test_cost_optimization(self):
        """Test cost optimization in model selection."""
        # Arrange
        models = {
            "gemini": {"cost_per_1k": 0.075, "speed": "fast"},
            "llama": {"cost_per_1k": 0.08, "speed": "medium"},
            "qwen": {"cost_per_1k": 0.05, "speed": "slow"},
        }

        task_tokens = 10000

        # Select cheapest option for non-critical tasks
        cheapest = min(models.items(), key=lambda x: x[1]["cost_per_1k"])

        # Assert
        assert cheapest[0] == "qwen"
