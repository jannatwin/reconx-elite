import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class LogicSimulator:
    """Simulates server-side reactions to malicious inputs before sending them."""

    def __init__(self, logs_dir: str = "./simulation_logs"):
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(exist_ok=True)
        self.logs_file = self.logs_dir / "simulation_logs.json"
        self.stealth_mode = False
        self.simulation_history: list[dict[str, Any]] = []
        self._load_history()

    def enable_stealth_mode(self) -> None:
        """Enable stealth mode - only simulate, never send real requests."""
        self.stealth_mode = True
        logger.info("Stealth Mode enabled - simulations only, no actual requests")

    def disable_stealth_mode(self) -> None:
        """Disable stealth mode - enable real request execution."""
        self.stealth_mode = False
        logger.info("Stealth Mode disabled - real requests enabled")

    async def simulate_request(
        self,
        endpoint: str,
        request_data: dict[str, Any],
        payload: dict[str, Any],
        tech_stack: list[str],
        model_router: Any,
    ) -> dict[str, Any]:
        """Simulate server response to a malicious payload."""
        logger.info(f"Simulating request to {endpoint} with payload {payload}")

        simulation_result = await model_router.simulate_request(
            request_data=request_data,
            payload=payload,
            tech_stack=tech_stack,
        )

        predicted_status, confidence = self._extract_prediction(simulation_result)

        simulation_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "endpoint": endpoint,
            "request_data": request_data,
            "input_payload": payload,
            "predicted_outcome": predicted_status,
            "prediction_confidence": confidence,
            "model_reasoning": simulation_result.get("output", ""),
            "actual_outcome": None,
        }

        self.simulation_history.append(simulation_entry)
        self._save_history()

        return {
            "endpoint": endpoint,
            "predicted_status": predicted_status,
            "confidence": confidence,
            "reasoning": simulation_result.get("output", ""),
            "should_execute": confidence >= 0.8 and not self.stealth_mode,
            "stealth_mode": self.stealth_mode,
        }

    async def test_financial_logic(
        self,
        endpoint: str,
        price_param: str,
        original_price: float,
        tech_stack: list[str],
        model_router: Any,
    ) -> dict[str, Any]:
        """Test for negative value or 100% discount bypasses in financial flows."""
        logger.info(f"Testing financial logic bypass on {endpoint} for {price_param}")

        test_payloads = [
            {price_param: -original_price, "description": "Negative price"},
            {price_param: 0, "description": "Zero price"},
            {price_param: -9999, "description": "Large negative value"},
        ]

        results = []
        for test_payload in test_payloads:
            sim_result = await self.simulate_request(
                endpoint=endpoint,
                request_data={"method": "POST", "endpoint": endpoint},
                payload=test_payload,
                tech_stack=tech_stack,
                model_router=model_router,
            )
            results.append(sim_result)

        return {
            "endpoint": endpoint,
            "price_parameter": price_param,
            "tests": results,
            "vulnerable": any(
                r["confidence"] >= 0.8 and "200" in r["predicted_status"]
                for r in results
            ),
        }

    async def refine_payload_for_bypass(
        self,
        original_payload: dict[str, Any],
        rejection_reason: str,
        endpoint: str,
        model_router: Any,
    ) -> dict[str, Any]:
        """Ask AI to refine payload to bypass server-side validation."""
        logger.info(f"Refining payload for {endpoint} - reason: {rejection_reason}")

        refined = await model_router.refine_payload(
            original_payload=original_payload,
            rejection_reason=rejection_reason,
        )

        return {
            "original_payload": original_payload,
            "rejection_reason": rejection_reason,
            "refined_suggestion": refined.get("output", ""),
            "model": refined.get("model"),
        }

    def _extract_prediction(
        self, simulation_result: dict[str, Any]
    ) -> tuple[str, float]:
        """Parse AI output to extract predicted HTTP status and confidence."""
        output = simulation_result.get("output", "").lower()

        status_code = "200"
        if "403" in output:
            status_code = "403"
        elif "401" in output:
            status_code = "401"
        elif "400" in output:
            status_code = "400"
        elif "500" in output:
            status_code = "500"
        elif "200" in output:
            status_code = "200"

        confidence = 0.5
        if "likely" in output or "definitely" in output or "will" in output:
            confidence = 0.85
        elif "probably" in output or "should" in output:
            confidence = 0.7
        elif "might" in output or "could" in output:
            confidence = 0.6
        elif "unlikely" in output or "won't" in output:
            confidence = 0.3

        return status_code, confidence

    def _load_history(self) -> None:
        """Load simulation history from file."""
        if self.logs_file.exists():
            try:
                with open(self.logs_file, "r") as f:
                    self.simulation_history = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load simulation history: {e}")
                self.simulation_history = []

    def _save_history(self) -> None:
        """Save simulation history to file."""
        try:
            with open(self.logs_file, "w") as f:
                json.dump(self.simulation_history, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save simulation history: {e}")

    def get_simulation_stats(self) -> dict[str, Any]:
        """Return statistics about simulations performed."""
        total_sims = len(self.simulation_history)
        successful = sum(
            1
            for s in self.simulation_history
            if "200" in s.get("predicted_outcome", "")
        )
        failed = sum(
            1
            for s in self.simulation_history
            if "400" in s.get("predicted_outcome", "")
            or "403" in s.get("predicted_outcome", "")
        )

        return {
            "total_simulations": total_sims,
            "successful_predictions": successful,
            "failed_predictions": failed,
            "stealth_mode_active": self.stealth_mode,
        }
