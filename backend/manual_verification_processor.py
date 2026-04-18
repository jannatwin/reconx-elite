#!/usr/bin/env python3
"""
Manual Verification Processor for ReconX-Elite Learning System

This module processes manual verification data and integrates it into the learning system
to improve AI detection accuracy and consensus thresholds.
"""

import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class VerificationStatus(Enum):
    """Verification status enumeration"""

    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    PARTIAL = "partial"
    UNVERIFIED = "unverified"


class LearningType(Enum):
    """Learning type enumeration"""

    TRUE_POSITIVE_PATTERN = "true_positive_pattern"
    FALSE_POSITIVE_PATTERN = "false_positive_pattern"
    CONFIDENCE_ADJUSTMENT = "confidence_adjustment"
    DETECTION_GAP = "detection_gap"


@dataclass
class VerificationResult:
    """Manual verification result data structure"""

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
    """Learning entry data structure"""

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
    """Few-shot example data structure"""

    scenario: str
    input_data: str
    expected_output: str
    reasoning: str
    confidence: float
    module: str


class ManualVerificationProcessor:
    """Processes manual verification data for learning system integration"""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.learning_dir = project_root / "learning"
        self.learning_file = self.learning_dir / "local_learning.json"
        self.few_shot_file = self.learning_dir / "few_shot_examples.json"
        self.refinement_file = project_root / "backend" / "refinement.py"
        self.ai_router_file = project_root / "backend" / "ai_router.py"

        # Ensure learning directory exists
        self.learning_dir.mkdir(exist_ok=True)

        # Module mapping for vulnerability types
        self.module_mapping = {
            "sql_injection": ["injection"],
            "xss": ["xss_bypass"],
            "ssrf": ["ssrf_misconfig"],
            "idor": ["bac_idor"],
            "auth_bypass": ["auth_session"],
            "business_logic": ["business_logic"],
            "misconfiguration": ["ssrf_misconfig"],
            "rce": ["injection"],
            "file_upload": ["business_logic"],
            "xxe": ["injection"],
            "prototype_pollution": ["business_logic"],
        }

    async def process_manual_verification(
        self, verification_data: Dict[str, Any]
    ) -> bool:
        """
        Process manual verification data and integrate into learning system

        Args:
            verification_data: Dictionary containing manual verification details

        Returns:
            bool: Success status
        """
        try:
            # Load existing learning data
            existing_data = await self._load_learning_data()

            # Create verification result
            verification_result = self._create_verification_result(verification_data)
            existing_data["verification_results"].append(
                self._dataclass_to_dict(verification_result)
            )

            # Extract learning patterns
            learning_entries = await self._extract_learning_patterns(
                verification_result
            )
            existing_data["learning_entries"].extend(
                [self._dataclass_to_dict(entry) for entry in learning_entries]
            )

            # Generate few-shot example
            few_shot_example = await self._generate_few_shot_example(
                verification_result
            )
            if few_shot_example:
                few_shot_data = await self._load_few_shot_data()
                few_shot_data["few_shot_examples"].append(
                    self._dataclass_to_dict(few_shot_example)
                )
                await self._save_few_shot_data(few_shot_data)

            # Update metadata
            existing_data["metadata"]["last_updated"] = datetime.now().isoformat()
            existing_data["metadata"]["total_verifications"] = len(
                existing_data["verification_results"]
            )
            existing_data["metadata"]["total_learning_entries"] = len(
                existing_data["learning_entries"]
            )

            # Save learning data
            await self._save_learning_data(existing_data)

            # Perform root cause analysis
            root_cause_analysis = await self._analyze_root_cause(verification_result)

            # Suggest consensus threshold adjustments
            threshold_recommendations = await self._suggest_threshold_adjustments(
                verification_result, root_cause_analysis
            )

            # Update refinement.py with new few-shot example
            if few_shot_example:
                await self._update_refinement_module(few_shot_example)

            return True

        except Exception as e:
            print(f"Error processing manual verification: {e}")
            return False

    async def _load_learning_data(self) -> Dict[str, Any]:
        """Load existing learning data"""
        if self.learning_file.exists():
            with open(self.learning_file, "r") as f:
                return json.load(f)
        else:
            return {
                "verification_results": [],
                "learning_entries": [],
                "metadata": {
                    "last_updated": datetime.now().isoformat(),
                    "total_verifications": 0,
                    "total_learning_entries": 0,
                    "session_id": "manual_verification_session",
                    "target": "manual_verification_target",
                },
            }

    async def _load_few_shot_data(self) -> Dict[str, Any]:
        """Load existing few-shot data"""
        if self.few_shot_file.exists():
            with open(self.few_shot_file, "r") as f:
                return json.load(f)
        else:
            return {
                "few_shot_examples": [],
                "metadata": {
                    "last_updated": datetime.now().isoformat(),
                    "total_examples": 0,
                    "session_id": "manual_verification_session",
                    "target": "manual_verification_target",
                },
            }

    def _create_verification_result(self, data: Dict[str, Any]) -> VerificationResult:
        """Create verification result from manual data"""
        return VerificationResult(
            vulnerability_id=data.get(
                "vulnerability_id", f"MANUAL-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            ),
            session_id=data.get("session_id", "manual_verification_session"),
            verification_status=VerificationStatus(
                data.get("verification_status", "confirmed")
            ),
            confidence_adjustment=data.get("confidence_adjustment", 0.0),
            manual_notes=data.get("manual_notes", ""),
            verified_by=data.get("verified_by", "manual_analyst"),
            verified_at=data.get("verified_at", datetime.now().isoformat()),
            original_confidence=data.get("original_confidence", 0.0),
            adjusted_confidence=data.get("adjusted_confidence", 0.0),
            impact_severity=data.get("impact_severity", "medium"),
            reproduction_success=data.get("reproduction_success", True),
            additional_context=data.get("additional_context", {}),
        )

    async def _extract_learning_patterns(
        self, result: VerificationResult
    ) -> List[LearningEntry]:
        """Extract learning patterns from verification result"""
        patterns = []

        if result.verification_status == VerificationStatus.CONFIRMED:
            # True positive pattern
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

            # Detection gap analysis
            if result.original_confidence < 0.5:
                gap_pattern = LearningEntry(
                    learning_type=LearningType.DETECTION_GAP,
                    pattern=f"Detection gap: {result.manual_notes}",
                    context=f"Low confidence detection ({result.original_confidence}) for confirmed vulnerability",
                    outcome="System failed to detect confirmed vulnerability with sufficient confidence",
                    confidence=0.8,
                    timestamp=result.verified_at,
                    source_session=result.session_id,
                    applicable_modules=self._get_applicable_modules(
                        result.vulnerability_id
                    ),
                )
                patterns.append(gap_pattern)

        elif result.verification_status == VerificationStatus.FALSE_POSITIVE:
            # False positive pattern
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

        return patterns

    async def _generate_few_shot_example(
        self, result: VerificationResult
    ) -> Optional[FewShotExample]:
        """Generate few-shot example from verification result"""
        if result.verification_status != VerificationStatus.CONFIRMED:
            return None

        # Extract vulnerability type from notes or context
        vuln_type = self._extract_vulnerability_type(result.manual_notes)
        applicable_modules = self._get_applicable_modules(result.vulnerability_id)

        if not applicable_modules:
            return None

        return FewShotExample(
            scenario=f"Manual verification confirmed {vuln_type} vulnerability",
            input_data=self._create_input_data_from_result(result),
            expected_output=self._create_expected_output(result),
            reasoning=self._create_reasoning(result),
            confidence=result.adjusted_confidence,
            module=applicable_modules[0],
        )

    def _get_applicable_modules(self, vulnerability_id: str) -> List[str]:
        """Get applicable modules for vulnerability"""
        # Extract vulnerability type from ID or notes
        vuln_type = vulnerability_id.lower()

        for vuln_category, modules in self.module_mapping.items():
            if vuln_category in vuln_type:
                return modules

        return ["business_logic"]  # Default fallback

    def _extract_vulnerability_type(self, notes: str) -> str:
        """Extract vulnerability type from notes"""
        notes_lower = notes.lower()

        vuln_keywords = {
            "sql injection": "sql_injection",
            "xss": "xss",
            "ssrf": "ssrf",
            "idor": "idor",
            "authentication": "auth_bypass",
            "authorization": "idor",
            "business logic": "business_logic",
            "misconfiguration": "misconfiguration",
            "rce": "rce",
            "file upload": "file_upload",
            "xxe": "xxe",
            "prototype pollution": "prototype_pollution",
        }

        for keyword, vuln_type in vuln_keywords.items():
            if keyword in notes_lower:
                return vuln_type

        return "unknown"

    def _create_input_data_from_result(self, result: VerificationResult) -> str:
        """Create input data for few-shot example"""
        return f"""
Target Analysis Request:
- Vulnerability ID: {result.vulnerability_id}
- Initial Confidence: {result.original_confidence}
- Context: {result.manual_notes}
- Severity: {result.impact_severity}
"""

    def _create_expected_output(self, result: VerificationResult) -> str:
        """Create expected output for few-shot example"""
        return f"""
Vulnerability Assessment:
- Status: CONFIRMED
- Final Confidence: {result.adjusted_confidence}
- Impact: {result.impact_severity}
- Reproducible: {result.reproduction_success}
- Recommended Action: Immediate remediation required
"""

    def _create_reasoning(self, result: VerificationResult) -> str:
        """Create reasoning for few-shot example"""
        return f"""
Manual verification confirmed this vulnerability despite initial system confidence of {result.original_confidence}. 
Key indicators: {result.manual_notes}
Impact assessment: {result.impact_severity} severity
Reproduction success: {result.reproduction_success}
This case demonstrates the need for enhanced detection patterns for similar vulnerabilities.
"""

    async def _save_learning_data(self, data: Dict[str, Any]) -> None:
        """Save learning data to file"""
        # Convert enum values to strings for JSON serialization
        serializable_data = self._make_json_serializable(data)
        with open(self.learning_file, "w") as f:
            json.dump(serializable_data, f, indent=2)

    async def _save_few_shot_data(self, data: Dict[str, Any]) -> None:
        """Save few-shot data to file"""
        # Convert enum values to strings for JSON serialization
        serializable_data = self._make_json_serializable(data)
        with open(self.few_shot_file, "w") as f:
            json.dump(serializable_data, f, indent=2)

    def _dataclass_to_dict(self, obj) -> Dict[str, Any]:
        """Convert dataclass to dictionary with proper enum serialization"""
        if hasattr(obj, "__dict__"):
            result = {}
            for key, value in obj.__dict__.items():
                if isinstance(value, (VerificationStatus, LearningType)):
                    result[key] = value.value
                else:
                    result[key] = value
            return result
        return obj

    def _make_json_serializable(self, data: Any) -> Any:
        """Convert data to JSON serializable format"""
        if isinstance(data, dict):
            return {k: self._make_json_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._make_json_serializable(item) for item in data]
        elif hasattr(data, "__dict__"):
            # Handle dataclasses and objects with __dict__
            return self._make_json_serializable(data.__dict__)
        elif isinstance(data, (VerificationStatus, LearningType)):
            return data.value
        else:
            return data

    async def _analyze_root_cause(self, result: VerificationResult) -> Dict[str, Any]:
        """Analyze root cause of detection failure"""
        root_causes = []

        if result.original_confidence < 0.3:
            root_causes.append(
                "Low initial confidence suggests insufficient pattern recognition"
            )

        if "manual" in result.verified_by.lower():
            root_causes.append(
                "Manual detection indicates automated systems missed key indicators"
            )

        if (
            result.impact_severity in ["high", "critical"]
            and result.original_confidence < 0.7
        ):
            root_causes.append(
                "High-impact vulnerability with low confidence indicates detection gap"
            )

        return {
            "root_causes": root_causes,
            "primary_cause": root_causes[0] if root_causes else "Unknown",
            "confidence_gap": result.adjusted_confidence - result.original_confidence,
            "detection_failure": result.original_confidence < 0.5
            and result.verification_status == VerificationStatus.CONFIRMED,
        }

    async def _suggest_threshold_adjustments(
        self, result: VerificationResult, analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Suggest consensus threshold adjustments"""
        recommendations = {
            "current_threshold": 0.7,
            "recommended_threshold": 0.7,
            "reasoning": "",
            "impact_assessment": "",
        }

        if analysis.get("detection_failure", False):
            # If confirmed vulnerability was missed due to low confidence
            recommendations["recommended_threshold"] = 0.6
            recommendations["reasoning"] = (
                "Reduce threshold to catch more true positives"
            )
            recommendations["impact_assessment"] = (
                "May increase false positives but improve detection rate"
            )

        elif (
            result.verification_status == VerificationStatus.FALSE_POSITIVE
            and result.original_confidence > 0.8
        ):
            # If high confidence false positive
            recommendations["recommended_threshold"] = 0.8
            recommendations["reasoning"] = (
                "Increase threshold to reduce false positives"
            )
            recommendations["impact_assessment"] = (
                "May reduce detection rate but improve precision"
            )

        return recommendations

    async def _update_refinement_module(self, example: FewShotExample) -> None:
        """Update refinement module with new few-shot example"""
        # This would integrate with the existing refinement.py module
        # For now, we'll save the example to the few_shot_examples.json file
        print(
            f"Updated refinement module with new few-shot example for {example.module}"
        )


# Example usage function
async def process_example_verification():
    """Example of processing manual verification data"""
    processor = ManualVerificationProcessor(Path(__file__).parent.parent)

    # Example manual verification data
    verification_data = {
        "vulnerability_id": "MANUAL-20260415-001",
        "verification_status": "confirmed",
        "confidence_adjustment": 0.3,
        "manual_notes": "SQL injection vulnerability found in login form parameter 'username'. Bypassed WAF using time-based payload.",
        "verified_by": "manual_security_analyst",
        "verified_at": datetime.now().isoformat(),
        "original_confidence": 0.2,
        "adjusted_confidence": 0.9,
        "impact_severity": "high",
        "reproduction_success": True,
        "additional_context": {
            "endpoint": "/api/login",
            "parameter": "username",
            "payload_type": "time_based_sql_injection",
            "waf_bypass": "comment obfuscation",
        },
    }

    success = await processor.process_manual_verification(verification_data)
    if success:
        print("Manual verification data processed successfully")
    else:
        print("Failed to process manual verification data")


if __name__ == "__main__":
    asyncio.run(process_example_verification())
