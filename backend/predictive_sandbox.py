"""
Predictive Sandbox - Phase 5 of Agentic Multi-Model Vulnerability Research Engine
Implements AI reasoning simulation and confidence-based execution
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ai_router import AIRouter
from logic_simulator import LogicSimulator
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


class ExecutionDecision(Enum):
    EXECUTE = "execute"
    SIMULATE_ONLY = "simulate_only"
    ABORT = "abort"


@dataclass
class SandboxTest:
    test_id: str
    endpoint: str
    method: str
    payload: Dict[str, Any]
    vulnerability_type: str
    predicted_response: Dict[str, Any]
    confidence_score: float
    execution_decision: ExecutionDecision
    actual_response: Optional[Dict[str, Any]] = None
    test_result: Optional[str] = None


@dataclass
class RiskAssessment:
    test_id: str
    risk_level: str  # low, medium, high, critical
    risk_factors: List[str]
    potential_impact: str
    confidence_score: float
    recommendation: str


class PredictiveSandbox:
    """Predictive sandbox for vulnerability testing with AI reasoning"""

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
        confidence_threshold: float = 0.8,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager
        self.confidence_threshold = confidence_threshold

        # Initialize logic simulator
        self.logic_simulator = LogicSimulator(
            session_id, target, ai_router, tool_runner, ws_manager
        )

        # Storage for results
        self.sandbox_tests: List[SandboxTest] = []
        self.risk_assessments: List[RiskAssessment] = []
        self.execution_history: List[Dict[str, Any]] = []

        # Risk assessment criteria
        self.risk_factors = {
            "data_destruction": ["delete", "drop", "truncate", "remove"],
            "data_exfiltration": ["dump", "export", "backup", "download"],
            "privilege_escalation": ["admin", "root", "sudo", "privilege"],
            "system_compromise": ["system", "config", "settings", "env"],
            "denial_of_service": ["flood", "dos", "crash", "timeout"],
            "financial_impact": ["payment", "transaction", "transfer", "refund"],
        }

    async def execute(
        self, vulnerability_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Execute predictive sandbox on vulnerability findings"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting predictive sandbox analysis...",
            phase="predictive_sandbox",
        )

        try:
            # Phase 5.1: Risk Assessment
            await self._assess_vulnerability_risks(vulnerability_findings)

            # Phase 5.2: AI Reasoning Simulation
            await self._simulate_vulnerability_exploitation(vulnerability_findings)

            # Phase 5.3: Confidence Calculation
            await self._calculate_confidence_scores()

            # Phase 5.4: Execution Decision Making
            await self._make_execution_decisions()

            # Phase 5.5: Conditional Execution
            await self._execute_high_confidence_tests()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Predictive sandbox completed: {len(self.sandbox_tests)} tests, "
                f"{len([t for t in self.sandbox_tests if t.execution_decision == ExecutionDecision.EXECUTE])} executed",
                phase="predictive_sandbox",
            )

            return results

        except Exception as e:
            logger.error(f"Predictive sandbox execution failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Predictive sandbox failed: {str(e)}",
                phase="predictive_sandbox",
            )
            raise

    async def _assess_vulnerability_risks(
        self, vulnerability_findings: List[Dict[str, Any]]
    ) -> None:
        """Assess risk levels for vulnerability findings"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Assessing vulnerability risks...",
            phase="risk_assessment",
        )

        for i, finding in enumerate(vulnerability_findings[:50]):  # Limit assessment
            try:
                test_id = f"risk_assessment_{i}"

                # Extract vulnerability details
                vuln_type = finding.get("vulnerability_type", "unknown")
                endpoint = finding.get("endpoint", "")
                payload = finding.get("payload", {})

                # Assess risk factors
                risk_factors = self._identify_risk_factors(vuln_type, payload)
                risk_level = self._calculate_risk_level(risk_factors)
                potential_impact = self._assess_potential_impact(
                    vuln_type, risk_factors
                )

                # Create risk assessment
                risk_assessment = RiskAssessment(
                    test_id=test_id,
                    risk_level=risk_level,
                    risk_factors=risk_factors,
                    potential_impact=potential_impact,
                    confidence_score=0.5,  # Initial confidence
                    recommendation=self._generate_recommendation(
                        risk_level, risk_factors
                    ),
                )

                self.risk_assessments.append(risk_assessment)

            except Exception as e:
                logger.debug(f"Risk assessment failed for finding {i}: {e}")

    def _identify_risk_factors(
        self, vuln_type: str, payload: Dict[str, Any]
    ) -> List[str]:
        """Identify risk factors for vulnerability"""
        risk_factors = []

        # Check payload for risk indicators
        payload_str = str(payload).lower()
        vuln_type_lower = vuln_type.lower()

        for factor, indicators in self.risk_factors.items():
            if any(indicator in payload_str for indicator in indicators):
                risk_factors.append(factor)

        # Check vulnerability type for specific risks
        if "sql injection" in vuln_type_lower:
            risk_factors.append("data_exfiltration")
            risk_factors.append("data_destruction")

        elif "command injection" in vuln_type_lower:
            risk_factors.append("system_compromise")
            risk_factors.append("privilege_escalation")

        elif "ssrf" in vuln_type_lower:
            risk_factors.append("system_compromise")
            risk_factors.append("data_exfiltration")

        elif "xss" in vuln_type_lower:
            risk_factors.append("privilege_escalation")

        elif "idor" in vuln_type_lower or "bac" in vuln_type_lower:
            risk_factors.append("privilege_escalation")
            risk_factors.append("data_exfiltration")

        elif "auth" in vuln_type_lower or "session" in vuln_type_lower:
            risk_factors.append("privilege_escalation")

        return risk_factors

    def _calculate_risk_level(self, risk_factors: List[str]) -> str:
        """Calculate risk level based on risk factors"""
        if not risk_factors:
            return "low"

        # High-risk factors
        high_risk_factors = [
            "data_destruction",
            "system_compromise",
            "privilege_escalation",
        ]
        medium_risk_factors = ["data_exfiltration", "financial_impact"]

        if any(factor in high_risk_factors for factor in risk_factors):
            return "critical"
        elif any(factor in medium_risk_factors for factor in risk_factors):
            return "high"
        elif len(risk_factors) >= 2:
            return "medium"
        else:
            return "low"

    def _assess_potential_impact(self, vuln_type: str, risk_factors: List[str]) -> str:
        """Assess potential impact of vulnerability"""
        impact_descriptions = {
            "data_destruction": "Potential data loss and system corruption",
            "data_exfiltration": "Unauthorized data access and exfiltration",
            "privilege_escalation": "Unauthorized administrative access",
            "system_compromise": "Full system compromise and control",
            "denial_of_service": "Service disruption and availability issues",
            "financial_impact": "Financial losses and fraudulent transactions",
        }

        impacts = []
        for factor in risk_factors:
            if factor in impact_descriptions:
                impacts.append(impact_descriptions[factor])

        return "; ".join(impacts) if impacts else "Unknown impact"

    def _generate_recommendation(self, risk_level: str, risk_factors: List[str]) -> str:
        """Generate recommendation based on risk assessment"""
        if risk_level == "critical":
            return (
                "Immediate remediation required. Do not execute exploit in production."
            )
        elif risk_level == "high":
            return (
                "High priority remediation. Execute only in isolated test environment."
            )
        elif risk_level == "medium":
            return "Schedule remediation. Execute with caution and monitoring."
        else:
            return "Standard remediation. Safe to execute with proper monitoring."

    async def _simulate_vulnerability_exploitation(
        self, vulnerability_findings: List[Dict[str, Any]]
    ) -> None:
        """Simulate vulnerability exploitation using AI reasoning"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Simulating vulnerability exploitation...",
            phase="exploitation_simulation",
        )

        for i, finding in enumerate(vulnerability_findings[:30]):  # Limit simulation
            try:
                test_id = f"simulation_{i}"

                # Extract vulnerability details
                endpoint = finding.get("endpoint", "")
                method = finding.get("method", "GET")
                payload = finding.get("payload", {})
                vuln_type = finding.get("vulnerability_type", "unknown")

                # Use AI to predict response
                predicted_response = await self._ai_predict_exploitation_result(
                    endpoint, method, payload, vuln_type
                )

                # Create sandbox test
                sandbox_test = SandboxTest(
                    test_id=test_id,
                    endpoint=endpoint,
                    method=method,
                    payload=payload,
                    vulnerability_type=vuln_type,
                    predicted_response=predicted_response,
                    confidence_score=0.0,  # Will be calculated later
                    execution_decision=ExecutionDecision.SIMULATE_ONLY,
                )

                self.sandbox_tests.append(sandbox_test)

            except Exception as e:
                logger.debug(f"Exploitation simulation failed for finding {i}: {e}")

    async def _ai_predict_exploitation_result(
        self, endpoint: str, method: str, payload: Dict[str, Any], vuln_type: str
    ) -> Dict[str, Any]:
        """Use AI to predict exploitation result"""
        prompt = f"""
        Predict the likely server response for the following vulnerability exploitation:
        
        Target: {self.target}
        Endpoint: {endpoint}
        Method: {method}
        Payload: {payload}
        Vulnerability Type: {vuln_type}
        
        Consider:
        1. Expected HTTP status code
        2. Response content indicators
        3. Error messages or success indicators
        4. Side effects or system changes
        5. Time delays or timeouts
        
        Return as JSON with keys:
        - status_code: expected HTTP status
        - response_content: expected response content
        - success_indicators: list of success indicators
        - error_indicators: list of error indicators
        - side_effects: potential side effects
        - confidence: prediction confidence (0.0-1.0)
        """

        try:
            result = await self.ai_router.call_model(
                role="deep_analyst",
                prompt=prompt,
                max_tokens=800,
                task_type="vulnerability_analysis",
            )

            if result.get("output"):
                try:
                    prediction = json.loads(result["output"])
                    return prediction

                except json.JSONDecodeError:
                    logger.warning("AI prediction response not valid JSON")

        except Exception as e:
            logger.error(f"AI exploitation prediction failed: {e}")

        # Fallback prediction
        return {
            "status_code": 200,
            "response_content": "Vulnerability exploitation successful",
            "success_indicators": ["success", "ok", "data"],
            "error_indicators": ["error", "forbidden", "unauthorized"],
            "side_effects": [],
            "confidence": 0.5,
        }

    async def _calculate_confidence_scores(self) -> None:
        """Calculate confidence scores for all tests"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Calculating confidence scores...",
            phase="confidence_calculation",
        )

        for test in self.sandbox_tests:
            try:
                # Get corresponding risk assessment
                risk_assessment = self._get_risk_assessment_for_test(test.test_id)

                # Calculate confidence score
                confidence = await self._calculate_test_confidence(
                    test, risk_assessment
                )
                test.confidence_score = confidence

            except Exception as e:
                logger.debug(
                    f"Confidence calculation failed for test {test.test_id}: {e}"
                )
                test.confidence_score = 0.5  # Default confidence

    def _get_risk_assessment_for_test(self, test_id: str) -> Optional[RiskAssessment]:
        """Get risk assessment for a specific test"""
        test_index = test_id.split("_")[-1]

        try:
            index = int(test_index)
            if index < len(self.risk_assessments):
                return self.risk_assessments[index]
        except (ValueError, IndexError):
            pass

        return None

    async def _calculate_test_confidence(
        self, test: SandboxTest, risk_assessment: Optional[RiskAssessment]
    ) -> float:
        """Calculate confidence score for a specific test"""
        confidence_factors = []

        # Factor 1: AI prediction confidence
        ai_confidence = test.predicted_response.get("confidence", 0.5)
        confidence_factors.append(ai_confidence)

        # Factor 2: Risk level adjustment
        if risk_assessment:
            risk_adjustments = {"critical": 0.3, "high": 0.5, "medium": 0.7, "low": 0.9}
            confidence_factors.append(
                risk_adjustments.get(risk_assessment.risk_level, 0.5)
            )

        # Factor 3: Vulnerability type reliability
        vuln_reliability = {
            "sql injection": 0.9,
            "command injection": 0.8,
            "xss": 0.7,
            "ssrf": 0.8,
            "idor": 0.6,
            "auth bypass": 0.7,
            "business logic": 0.5,
        }

        vuln_type_lower = test.vulnerability_type.lower()
        reliability = 0.5  # Default

        for vuln_type, reliability_score in vuln_reliability.items():
            if vuln_type in vuln_type_lower:
                reliability = reliability_score
                break

        confidence_factors.append(reliability)

        # Factor 4: Historical execution success rate
        historical_confidence = self._get_historical_confidence(test.vulnerability_type)
        confidence_factors.append(historical_confidence)

        # Calculate weighted average
        weights = [0.3, 0.2, 0.3, 0.2]  # AI, risk, reliability, historical

        confidence = sum(
            factor * weight for factor, weight in zip(confidence_factors, weights)
        )

        return min(max(confidence, 0.0), 1.0)  # Clamp between 0 and 1

    def _get_historical_confidence(self, vuln_type: str) -> float:
        """Get historical confidence for vulnerability type"""
        # Filter execution history by vulnerability type
        type_history = [
            execution
            for execution in self.execution_history
            if execution.get("vulnerability_type", "").lower() == vuln_type.lower()
        ]

        if not type_history:
            return 0.5  # Default confidence

        # Calculate success rate
        successful_executions = [
            execution for execution in type_history if execution.get("success", False)
        ]

        success_rate = len(successful_executions) / len(type_history)

        return success_rate

    async def _make_execution_decisions(self) -> None:
        """Make execution decisions based on confidence scores"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Making execution decisions...",
            phase="execution_decision",
        )

        for test in self.sandbox_tests:
            try:
                # Get risk assessment
                risk_assessment = self._get_risk_assessment_for_test(test.test_id)

                # Make decision
                decision = await self._make_execution_decision(test, risk_assessment)
                test.execution_decision = decision

            except Exception as e:
                logger.debug(f"Execution decision failed for test {test.test_id}: {e}")
                test.execution_decision = ExecutionDecision.SIMULATE_ONLY

    async def _make_execution_decision(
        self, test: SandboxTest, risk_assessment: Optional[RiskAssessment]
    ) -> ExecutionDecision:
        """Make execution decision for a specific test"""
        confidence = test.confidence_score

        # Check risk level
        risk_level = "low"
        if risk_assessment:
            risk_level = risk_assessment.risk_level

        # Decision logic
        if risk_level == "critical":
            # Never execute critical risks
            return ExecutionDecision.ABORT

        elif risk_level == "high":
            # Execute high risks only with very high confidence
            if confidence >= 0.95:
                return ExecutionDecision.EXECUTE
            else:
                return ExecutionDecision.SIMULATE_ONLY

        elif risk_level == "medium":
            # Execute medium risks with good confidence
            if confidence >= self.confidence_threshold:
                return ExecutionDecision.EXECUTE
            else:
                return ExecutionDecision.SIMULATE_ONLY

        else:  # low risk
            # Execute low risks with moderate confidence
            if confidence >= 0.6:
                return ExecutionDecision.EXECUTE
            else:
                return ExecutionDecision.SIMULATE_ONLY

    async def _execute_high_confidence_tests(self) -> None:
        """Execute tests that meet confidence threshold"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Executing high confidence tests...",
            phase="test_execution",
        )

        executable_tests = [
            test
            for test in self.sandbox_tests
            if test.execution_decision == ExecutionDecision.EXECUTE
        ]

        for test in executable_tests:
            try:
                await self._execute_sandbox_test(test)
            except Exception as e:
                logger.debug(f"Test execution failed for {test.test_id}: {e}")
                test.test_result = f"Execution failed: {str(e)}"

    async def _execute_sandbox_test(self, test: SandboxTest) -> None:
        """Execute a sandbox test"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            f"Executing test {test.test_id} (confidence: {test.confidence_score:.2f})",
            phase="test_execution",
        )

        try:
            # Execute the actual request
            start_time = time.time()

            response = await self._execute_test_request(test)

            execution_time = time.time() - start_time

            # Store actual response
            test.actual_response = response

            # Evaluate test result
            test_result = self._evaluate_test_result(test)
            test.test_result = test_result

            # Update execution history
            self._update_execution_history(test, test_result, execution_time)

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Test {test.test_id} completed: {test_result}",
                phase="test_execution",
            )

        except Exception as e:
            logger.error(f"Sandbox test execution failed: {e}")
            test.test_result = f"Execution error: {str(e)}"

    async def _execute_test_request(self, test: SandboxTest) -> Dict[str, Any]:
        """Execute the actual test request"""
        try:
            headers = {}

            # Add authentication if available
            if hasattr(self, "session_tokens") and self.session_tokens:
                for token_name, token in self.session_tokens.items():
                    if token:
                        if token.startswith("Bearer "):
                            headers["Authorization"] = token
                        elif token.startswith("ey"):  # JWT
                            headers["Authorization"] = f"Bearer {token}"
                        else:
                            headers["Cookie"] = f"sessionid={token}"
                        break

            # Execute request based on method
            if test.method.upper() == "GET":
                if test.payload:
                    query_params = "&".join(
                        [f"{k}={v}" for k, v in test.payload.items()]
                    )
                    url = f"{test.endpoint}?{query_params}"
                else:
                    url = test.endpoint

                result = await self.tool_runner.run_tool(
                    "http_request", {"url": url, "method": "GET", "headers": headers}
                )
            else:
                result = await self.tool_runner.run_tool(
                    "http_request",
                    {
                        "url": test.endpoint,
                        "method": test.method,
                        "json": test.payload,
                        "headers": {**headers, "Content-Type": "application/json"},
                    },
                )

            return result or {}

        except Exception as e:
            logger.debug(f"Test request execution failed: {e}")
            return {"error": str(e)}

    def _evaluate_test_result(self, test: SandboxTest) -> str:
        """Evaluate test result against prediction"""
        if not test.actual_response:
            return "failed_no_response"

        actual_status = test.actual_response.get("status_code", 0)
        predicted_status = test.predicted_response.get("status_code", 200)

        # Check if status matches prediction
        if actual_status == predicted_status:
            # Check for success indicators
            actual_data = str(test.actual_response.get("data", "")).lower()
            success_indicators = test.predicted_response.get("success_indicators", [])

            if any(indicator in actual_data for indicator in success_indicators):
                return "success_vulnerability_confirmed"
            else:
                return "partial_match"

        # Check for error indicators
        error_indicators = test.predicted_response.get("error_indicators", [])
        if any(indicator in str(actual_status) for indicator in error_indicators):
            return "failed_as_expected"

        return "unexpected_result"

    def _update_execution_history(
        self, test: SandboxTest, result: str, execution_time: float
    ) -> None:
        """Update execution history"""
        history_entry = {
            "timestamp": time.time(),
            "test_id": test.test_id,
            "vulnerability_type": test.vulnerability_type,
            "confidence_score": test.confidence_score,
            "execution_decision": test.execution_decision.value,
            "result": result,
            "execution_time": execution_time,
            "success": result.startswith("success"),
        }

        self.execution_history.append(history_entry)

        # Keep history size manageable
        if len(self.execution_history) > 1000:
            self.execution_history = self.execution_history[-500:]

    def _compile_results(self) -> Dict[str, Any]:
        """Compile predictive sandbox results"""
        executed_tests = [
            t
            for t in self.sandbox_tests
            if t.execution_decision == ExecutionDecision.EXECUTE
        ]
        successful_tests = [
            t
            for t in executed_tests
            if t.test_result and t.test_result.startswith("success")
        ]

        return {
            "target": self.target,
            "session_id": self.session_id,
            "module": "predictive_sandbox",
            "confidence_threshold": self.confidence_threshold,
            "risk_assessments": {
                "total_count": len(self.risk_assessments),
                "critical_count": len(
                    [r for r in self.risk_assessments if r.risk_level == "critical"]
                ),
                "high_count": len(
                    [r for r in self.risk_assessments if r.risk_level == "high"]
                ),
                "results": [asdict(assessment) for assessment in self.risk_assessments],
                "risk_distribution": {
                    level: len(
                        [r for r in self.risk_assessments if r.risk_level == level]
                    )
                    for level in ["critical", "high", "medium", "low"]
                },
            },
            "sandbox_tests": {
                "total_count": len(self.sandbox_tests),
                "executed_count": len(executed_tests),
                "successful_count": len(successful_tests),
                "aborted_count": len(
                    [
                        t
                        for t in self.sandbox_tests
                        if t.execution_decision == ExecutionDecision.ABORT
                    ]
                ),
                "results": [asdict(test) for test in self.sandbox_tests],
                "execution_decisions": {
                    decision: len(
                        [
                            t
                            for t in self.sandbox_tests
                            if t.execution_decision == ExecutionDecision(decision)
                        ]
                    )
                    for decision in ["EXECUTE", "SIMULATE_ONLY", "ABORT"]
                },
            },
            "execution_history": {
                "total_executions": len(self.execution_history),
                "success_rate": len(
                    [h for h in self.execution_history if h.get("success", False)]
                )
                / max(len(self.execution_history), 1),
                "average_execution_time": sum(
                    h.get("execution_time", 0) for h in self.execution_history
                )
                / max(len(self.execution_history), 1),
                "recent_executions": [h for h in self.execution_history[-10:]],
            },
            "summary": {
                "total_tests_analyzed": len(self.sandbox_tests),
                "tests_executed": len(executed_tests),
                "vulnerabilities_confirmed": len(successful_tests),
                "execution_success_rate": len(successful_tests)
                / max(len(executed_tests), 1),
                "average_confidence": sum(
                    t.confidence_score for t in self.sandbox_tests
                )
                / max(len(self.sandbox_tests), 1),
                "recommendation": "Review high-confidence successful tests for immediate remediation",
            },
        }
