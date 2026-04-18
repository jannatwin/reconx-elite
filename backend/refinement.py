"""
Refinement Module - Learning Feedback System
Implements continuous learning from manual verification results
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ai_router import AIRouter
from tool_runner import ToolRunner
from websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    PARTIAL = "partial"
    DISPUTED = "disputed"


class LearningType(Enum):
    FALSE_POSITIVE_PATTERN = "false_positive_pattern"
    TRUE_POSITIVE_PATTERN = "true_positive_pattern"
    CONFIDENCE_ADJUSTMENT = "confidence_adjustment"
    PAYLOAD_IMPROVEMENT = "payload_improvement"
    TECHNIQUE_REFINEMENT = "technique_refinement"


@dataclass
class VerificationResult:
    vulnerability_id: str
    session_id: str
    verification_status: VerificationStatus
    confidence_adjustment: float
    manual_notes: str
    verified_by: str
    verified_at: str
    original_confidence: float
    adjusted_confidence: float
    impact_severity: str
    reproduction_success: bool
    additional_context: Dict[str, Any]


@dataclass
class LearningEntry:
    learning_type: LearningType
    pattern: str
    context: str
    outcome: str
    confidence: float
    timestamp: str
    source_session: str
    applicable_modules: List[str]


@dataclass
class FewShotExample:
    scenario: str
    input_data: str
    expected_output: str
    reasoning: str
    confidence: float
    module: str


class Refinement:
    """Learning feedback system for continuous improvement"""

    def __init__(
        self,
        session_id: str,
        target: str,
        ai_router: AIRouter,
        tool_runner: ToolRunner,
        ws_manager: WebSocketManager,
    ):
        self.session_id = session_id
        self.target = target
        self.ai_router = ai_router
        self.tool_runner = tool_runner
        self.ws_manager = ws_manager

        # Storage for learning data
        self.verification_results: List[VerificationResult] = []
        self.learning_entries: List[LearningEntry] = []
        self.few_shot_examples: List[FewShotExample] = []

        # File paths
        self.learning_dir = Path("learning")
        self.learning_file = self.learning_dir / "local_learning.json"
        self.few_shot_file = self.learning_dir / "few_shot_examples.json"

        # Ensure learning directory exists
        self.learning_dir.mkdir(exist_ok=True)

        # Module mappings
        self.module_mapping = {
            "bac_idor": ["access_control", "idor", "authorization"],
            "injection": ["sql_injection", "command_injection", "code_injection"],
            "ssrf_misconfig": ["ssrf", "misconfiguration", "security_headers"],
            "xss_bypass": ["xss", "cross_site_scripting", "waf_bypass"],
            "auth_session": ["authentication", "session_management", "jwt"],
            "business_logic": ["business_logic", "logic_flaws", "race_conditions"],
        }

    async def execute(self) -> Dict[str, Any]:
        """Execute refinement and learning feedback processing"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Starting refinement and learning feedback processing...",
            phase="refinement",
        )

        try:
            # Load existing learning data
            await self._load_learning_data()

            # Process new verification results
            await self._process_verification_results()

            # Extract learning patterns
            await self._extract_learning_patterns()

            # Generate few-shot examples
            await self._generate_few_shot_examples()

            # Update AI system prompts
            await self._update_ai_prompts()

            # Save learning data
            await self._save_learning_data()

            # Compile results
            results = self._compile_results()

            await self.ws_manager.send_log(
                self.session_id,
                "success",
                f"Refinement completed: {len(self.learning_entries)} learning patterns extracted",
                phase="refinement",
            )

            return results

        except Exception as e:
            logger.error(f"Refinement execution failed: {e}")
            await self.ws_manager.send_log(
                self.session_id,
                "error",
                f"Refinement failed: {str(e)}",
                phase="refinement",
            )
            raise

    async def _load_learning_data(self) -> None:
        """Load existing learning data from files"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Loading existing learning data...",
            phase="refinement",
        )

        # Load verification results
        if self.learning_file.exists():
            try:
                with open(self.learning_file, "r") as f:
                    learning_data = json.load(f)

                self.verification_results = []
                for result_data in learning_data.get("verification_results", []):
                    if isinstance(result_data, dict):
                        result = VerificationResult(
                            vulnerability_id=result_data["vulnerability_id"],
                            session_id=result_data["session_id"],
                            verification_status=VerificationStatus(
                                result_data["verification_status"]
                            ),
                            confidence_adjustment=result_data["confidence_adjustment"],
                            manual_notes=result_data["manual_notes"],
                            verified_by=result_data["verified_by"],
                            verified_at=result_data["verified_at"],
                            original_confidence=result_data["original_confidence"],
                            adjusted_confidence=result_data["adjusted_confidence"],
                            impact_severity=result_data["impact_severity"],
                            reproduction_success=result_data["reproduction_success"],
                            additional_context=result_data.get(
                                "additional_context", {}
                            ),
                        )
                        self.verification_results.append(result)

                # Load learning entries
                for entry_data in learning_data.get("learning_entries", []):
                    if isinstance(entry_data, dict):
                        entry = LearningEntry(
                            learning_type=LearningType(entry_data["learning_type"]),
                            pattern=entry_data["pattern"],
                            context=entry_data["context"],
                            outcome=entry_data["outcome"],
                            confidence=entry_data["confidence"],
                            timestamp=entry_data["timestamp"],
                            source_session=entry_data["source_session"],
                            applicable_modules=entry_data["applicable_modules"],
                        )
                        self.learning_entries.append(entry)

                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"Loaded {len(self.verification_results)} verification results and {len(self.learning_entries)} learning entries",
                    phase="refinement",
                )

            except Exception as e:
                logger.error(f"Failed to load learning data: {e}")

        # Load few-shot examples
        if self.few_shot_file.exists():
            try:
                with open(self.few_shot_file, "r") as f:
                    few_shot_data = json.load(f)

                self.few_shot_examples = []
                for example_data in few_shot_data.get("few_shot_examples", []):
                    if isinstance(example_data, dict):
                        example = FewShotExample(
                            scenario=example_data["scenario"],
                            input_data=example_data["input_data"],
                            expected_output=example_data["expected_output"],
                            reasoning=example_data["reasoning"],
                            confidence=example_data["confidence"],
                            module=example_data["module"],
                        )
                        self.few_shot_examples.append(example)

                await self.ws_manager.send_log(
                    self.session_id,
                    "info",
                    f"Loaded {len(self.few_shot_examples)} few-shot examples",
                    phase="refinement",
                )

            except Exception as e:
                logger.error(f"Failed to load few-shot examples: {e}")

    async def _process_verification_results(self) -> None:
        """Process new verification results and extract learning patterns"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Processing verification results...",
            phase="refinement",
        )

        # In a real implementation, this would load new verification results
        # For now, we'll process existing results

        for result in self.verification_results:
            try:
                # Extract learning patterns from verification result
                learning_patterns = await self._extract_patterns_from_verification(
                    result
                )

                for pattern in learning_patterns:
                    self.learning_entries.append(pattern)

            except Exception as e:
                logger.debug(
                    f"Failed to process verification result {result.vulnerability_id}: {e}"
                )

    async def _extract_patterns_from_verification(
        self, result: VerificationResult
    ) -> List[LearningEntry]:
        """Extract learning patterns from a verification result"""
        patterns = []

        # False positive pattern
        if result.verification_status == VerificationStatus.FALSE_POSITIVE:
            pattern = LearningEntry(
                learning_type=LearningType.FALSE_POSITIVE_PATTERN,
                pattern=f"False positive detected: {result.manual_notes}",
                context=f"Vulnerability {result.vulnerability_id} with confidence {result.original_confidence}",
                outcome="Manual verification confirmed false positive",
                confidence=0.9,
                timestamp=result.verified_at,
                source_session=result.session_id,
                applicable_modules=self._get_applicable_modules(
                    result.vulnerability_id
                ),
            )
            patterns.append(pattern)

        # True positive pattern
        elif result.verification_status == VerificationStatus.CONFIRMED:
            pattern = LearningEntry(
                learning_type=LearningType.TRUE_POSITIVE_PATTERN,
                pattern=f"Confirmed vulnerability: {result.manual_notes}",
                context=f"Vulnerability {result.vulnerability_id} with confidence {result.original_confidence}",
                outcome="Manual verification confirmed true positive",
                confidence=0.9,
                timestamp=result.verified_at,
                source_session=result.session_id,
                applicable_modules=self._get_applicable_modules(
                    result.vulnerability_id
                ),
            )
            patterns.append(pattern)

        # Confidence adjustment pattern
        if abs(result.confidence_adjustment) > 0.1:
            pattern = LearningEntry(
                learning_type=LearningType.CONFIDENCE_ADJUSTMENT,
                pattern=f"Confidence adjusted by {result.confidence_adjustment}",
                context=f"Original: {result.original_confidence}, Adjusted: {result.adjusted_confidence}",
                outcome=result.manual_notes,
                confidence=0.8,
                timestamp=result.verified_at,
                source_session=result.session_id,
                applicable_modules=self._get_applicable_modules(
                    result.vulnerability_id
                ),
            )
            patterns.append(pattern)

        return patterns

    def _get_applicable_modules(self, vulnerability_id: str) -> List[str]:
        """Get applicable modules for a vulnerability ID"""
        # Extract module from vulnerability ID or context
        for module, keywords in self.module_mapping.items():
            if any(keyword in vulnerability_id.lower() for keyword in keywords):
                return [module]

        return ["general"]  # Default to general if no specific module found

    async def _extract_learning_patterns(self) -> None:
        """Extract learning patterns from accumulated data"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Extracting learning patterns...",
            phase="refinement",
        )

        # Use AI to analyze patterns
        await self._ai_analyze_patterns()

    async def _ai_analyze_patterns(self) -> None:
        """Use AI to analyze and extract learning patterns"""
        # Group learning entries by type
        grouped_entries = {}
        for entry in self.learning_entries:
            learning_type = entry.learning_type.value
            if learning_type not in grouped_entries:
                grouped_entries[learning_type] = []
            grouped_entries[learning_type].append(entry)

        # Analyze each group
        for learning_type, entries in grouped_entries.items():
            if len(entries) >= 3:  # Only analyze if we have enough data
                try:
                    await self._analyze_pattern_group(learning_type, entries)
                except Exception as e:
                    logger.debug(
                        f"Failed to analyze pattern group {learning_type}: {e}"
                    )

    async def _analyze_pattern_group(
        self, learning_type: str, entries: List[LearningEntry]
    ) -> None:
        """Analyze a specific pattern group using AI"""
        # Prepare data for AI analysis
        entries_data = []
        for entry in entries[-20:]:  # Limit to last 20 entries
            entries_data.append(
                {
                    "pattern": entry.pattern,
                    "context": entry.context,
                    "outcome": entry.outcome,
                    "confidence": entry.confidence,
                }
            )

        prompt = f"""
        Analyze the following learning patterns for {learning_type}:
        
        Patterns:
        {json.dumps(entries_data, indent=2)}
        
        Extract key insights and create actionable recommendations:
        1. Common patterns or indicators
        2. Confidence adjustment rules
        3. False positive indicators
        4. Improvement suggestions
        
        Return as JSON: {{"insights": ["insight1"], "recommendations": ["rec1"], "confidence_rules": [{"condition": "rule", "adjustment": 0.1}]}}
        """

        try:
            result = await self.ai_router.call_model(
                role="deep_analyst",  # Use LLAMA 3.3 70B for pattern analysis
                prompt=prompt,
                max_tokens=800,
                task_type="pattern_analysis",
            )

            if result.get("output"):
                try:
                    analysis = json.loads(result["output"])

                    # Create learning entry from AI insights
                    for insight in analysis.get("insights", []):
                        learning_entry = LearningEntry(
                            learning_type=LearningType(learning_type),
                            pattern=insight,
                            context="AI-generated insight",
                            outcome="Pattern analysis",
                            confidence=0.7,
                            timestamp=datetime.now().isoformat(),
                            source_session=self.session_id,
                            applicable_modules=["general"],
                        )
                        self.learning_entries.append(learning_entry)

                except json.JSONDecodeError:
                    logger.warning("AI pattern analysis response not valid JSON")

        except Exception as e:
            logger.error(f"AI pattern analysis failed: {e}")

    async def _generate_few_shot_examples(self) -> None:
        """Generate few-shot examples for AI system prompts"""
        await self.ws_manager.send_log(
            self.session_id,
            "info",
            "Generating few-shot examples...",
            phase="refinement",
        )

        # Generate examples from confirmed vulnerabilities
        confirmed_results = [
            r
            for r in self.verification_results
            if r.verification_status == VerificationStatus.CONFIRMED
        ]

        for result in confirmed_results[:10]:  # Limit to 10 examples
            try:
                example = await self._create_few_shot_example(result)
                if example:
                    self.few_shot_examples.append(example)
            except Exception as e:
                logger.debug(
                    f"Failed to create few-shot example for {result.vulnerability_id}: {e}"
                )

    async def _create_few_shot_example(
        self, result: VerificationResult
    ) -> Optional[FewShotExample]:
        """Create a few-shot example from a verification result"""
        prompt = f"""
        Create a few-shot learning example from this verified vulnerability:
        
        Vulnerability ID: {result.vulnerability_id}
        Verification Status: {result.verification_status.value}
        Manual Notes: {result.manual_notes}
        Original Confidence: {result.original_confidence}
        Adjusted Confidence: {result.adjusted_confidence}
        Impact Severity: {result.impact_severity}
        Reproduction Success: {result.reproduction_success}
        
        Create a structured example with:
        1. Scenario description
        2. Input data (what the AI sees)
        3. Expected output (what the AI should produce)
        4. Reasoning (why this is the correct output)
        
        Return as JSON: {{"scenario": "description", "input_data": "input", "expected_output": "output", "reasoning": "reasoning"}}
        """

        try:
            ai_result = await self.ai_router.call_model(
                role="deep_analyst",
                prompt=prompt,
                max_tokens=600,
                task_type="example_generation",
            )

            if ai_result.get("output"):
                try:
                    example_data = json.loads(ai_result["output"])

                    return FewShotExample(
                        scenario=example_data.get("scenario", ""),
                        input_data=example_data.get("input_data", ""),
                        expected_output=example_data.get("expected_output", ""),
                        reasoning=example_data.get("reasoning", ""),
                        confidence=result.adjusted_confidence,
                        module=self._get_applicable_modules(result.vulnerability_id)[0],
                    )

                except json.JSONDecodeError:
                    logger.warning("AI few-shot example response not valid JSON")

        except Exception as e:
            logger.error(f"Few-shot example generation failed: {e}")

        return None

    async def _update_ai_prompts(self) -> None:
        """Update AI system prompts with learning context"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Updating AI system prompts...", phase="refinement"
        )

        # Create learning context for AI prompts
        learning_context = await self._create_learning_context()

        # Save learning context for AI router to use
        context_file = self.learning_dir / "ai_learning_context.json"
        try:
            with open(context_file, "w") as f:
                json.dump(learning_context, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save learning context: {e}")

    async def _create_learning_context(self) -> Dict[str, Any]:
        """Create learning context for AI system prompts"""
        # Get recent high-confidence learning entries
        recent_entries = sorted(
            [e for e in self.learning_entries if e.confidence > 0.7],
            key=lambda x: x.timestamp,
            reverse=True,
        )[:20]

        # Get relevant few-shot examples
        relevant_examples = [e for e in self.few_shot_examples if e.confidence > 0.8][
            :10
        ]

        # Calculate confidence adjustments by module
        confidence_adjustments = {}
        for result in self.verification_results:
            modules = self._get_applicable_modules(result.vulnerability_id)
            for module in modules:
                if module not in confidence_adjustments:
                    confidence_adjustments[module] = []
                confidence_adjustments[module].append(result.confidence_adjustment)

        # Calculate average adjustments
        avg_adjustments = {}
        for module, adjustments in confidence_adjustments.items():
            if adjustments:
                avg_adjustments[module] = sum(adjustments) / len(adjustments)

        return {
            "learning_entries": [asdict(entry) for entry in recent_entries],
            "few_shot_examples": [asdict(example) for example in relevant_examples],
            "confidence_adjustments": avg_adjustments,
            "false_positive_patterns": [
                entry.pattern
                for entry in recent_entries
                if entry.learning_type == LearningType.FALSE_POSITIVE_PATTERN
            ],
            "true_positive_patterns": [
                entry.pattern
                for entry in recent_entries
                if entry.learning_type == LearningType.TRUE_POSITIVE_PATTERN
            ],
            "generated_at": datetime.now().isoformat(),
            "session_id": self.session_id,
            "target": self.target,
        }

    async def _save_learning_data(self) -> None:
        """Save learning data to files"""
        await self.ws_manager.send_log(
            self.session_id, "info", "Saving learning data...", phase="refinement"
        )

        # Save verification results and learning entries
        learning_data = {
            "verification_results": [
                asdict(result) for result in self.verification_results
            ],
            "learning_entries": [asdict(entry) for entry in self.learning_entries],
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "total_verifications": len(self.verification_results),
                "total_learning_entries": len(self.learning_entries),
                "session_id": self.session_id,
                "target": self.target,
            },
        }

        try:
            with open(self.learning_file, "w") as f:
                json.dump(learning_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")

        # Save few-shot examples
        few_shot_data = {
            "few_shot_examples": [
                asdict(example) for example in self.few_shot_examples
            ],
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "total_examples": len(self.few_shot_examples),
                "session_id": self.session_id,
                "target": self.target,
            },
        }

        try:
            with open(self.few_shot_file, "w") as f:
                json.dump(few_shot_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save few-shot examples: {e}")

    def _compile_results(self) -> Dict[str, Any]:
        """Compile refinement results"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "module": "refinement",
            "verification_results": {
                "total_count": len(self.verification_results),
                "confirmed_count": len(
                    [
                        r
                        for r in self.verification_results
                        if r.verification_status == VerificationStatus.CONFIRMED
                    ]
                ),
                "false_positive_count": len(
                    [
                        r
                        for r in self.verification_results
                        if r.verification_status == VerificationStatus.FALSE_POSITIVE
                    ]
                ),
                "partial_count": len(
                    [
                        r
                        for r in self.verification_results
                        if r.verification_status == VerificationStatus.PARTIAL
                    ]
                ),
                "average_confidence_adjustment": sum(
                    r.confidence_adjustment for r in self.verification_results
                )
                / max(len(self.verification_results), 1),
            },
            "learning_entries": {
                "total_count": len(self.learning_entries),
                "learning_types": list(
                    set(entry.learning_type.value for entry in self.learning_entries)
                ),
                "high_confidence_count": len(
                    [e for e in self.learning_entries if e.confidence > 0.8]
                ),
                "results": [
                    asdict(entry) for entry in self.learning_entries[:20]
                ],  # Limit for response size
            },
            "few_shot_examples": {
                "total_count": len(self.few_shot_examples),
                "modules": list(
                    set(example.module for example in self.few_shot_examples)
                ),
                "high_confidence_count": len(
                    [e for e in self.few_shot_examples if e.confidence > 0.8]
                ),
                "results": [
                    asdict(example) for example in self.few_shot_examples[:10]
                ],  # Limit for response size
            },
            "summary": {
                "total_verifications": len(self.verification_results),
                "total_learning_entries": len(self.learning_entries),
                "total_few_shot_examples": len(self.few_shot_examples),
                "learning_rate": len(self.learning_entries)
                / max(len(self.verification_results), 1),
                "recommendation": "Continue manual verification to improve learning accuracy",
            },
        }

    async def add_verification_result(self, verification_data: Dict[str, Any]) -> bool:
        """Add a new verification result"""
        try:
            result = VerificationResult(
                vulnerability_id=verification_data["vulnerability_id"],
                session_id=verification_data.get("session_id", self.session_id),
                verification_status=VerificationStatus(
                    verification_data["verification_status"]
                ),
                confidence_adjustment=verification_data.get(
                    "confidence_adjustment", 0.0
                ),
                manual_notes=verification_data.get("manual_notes", ""),
                verified_by=verification_data.get("verified_by", "manual"),
                verified_at=verification_data.get(
                    "verified_at", datetime.now().isoformat()
                ),
                original_confidence=verification_data.get("original_confidence", 0.0),
                adjusted_confidence=verification_data.get("adjusted_confidence", 0.0),
                impact_severity=verification_data.get("impact_severity", "medium"),
                reproduction_success=verification_data.get(
                    "reproduction_success", True
                ),
                additional_context=verification_data.get("additional_context", {}),
            )

            self.verification_results.append(result)

            await self.ws_manager.send_log(
                self.session_id,
                "info",
                f"Added verification result for {result.vulnerability_id}",
                phase="refinement",
            )

            return True

        except Exception as e:
            logger.error(f"Failed to add verification result: {e}")
            return False
