#!/usr/bin/env python3
"""
Demonstration script for processing manual verification data
"""

import asyncio
from pathlib import Path
from datetime import datetime
from manual_verification_processor import ManualVerificationProcessor


async def demo_sql_injection_verification():
    """Demo processing a manually verified SQL injection vulnerability"""
    processor = ManualVerificationProcessor(Path(__file__).parent.parent)

    # Example: Manual verification of missed SQL injection
    verification_data = {
        "vulnerability_id": "MANUAL-SQLINJ-20260415-001",
        "session_id": "reconx-elite-session-001",
        "verification_status": "confirmed",
        "confidence_adjustment": 0.4,
        "manual_notes": "Time-based SQL injection in login form. Original automated scan missed this due to WAF protection. Manual testing with comment-based payload bypass revealed vulnerability in username parameter.",
        "verified_by": "security_analyst_john",
        "verified_at": datetime.now().isoformat(),
        "original_confidence": 0.15,  # Very low confidence, almost missed
        "adjusted_confidence": 0.95,  # High confidence after manual verification
        "impact_severity": "critical",
        "reproduction_success": True,
        "additional_context": {
            "target": "api.example.com",
            "endpoint": "/api/v2/auth/login",
            "parameter": "username",
            "payload": "admin'/**/AND/**/(SELECT/**/SUBSTRING(password,1,1)/**/FROM/**/users/**/WHERE/**/id=1)='a",
            "bypass_technique": "comment obfuscation",
            "waf_detected": True,
            "database_type": "MySQL",
            "response_time_delay": "5.2 seconds",
        },
    }

    print("Processing SQL injection manual verification...")
    success = await processor.process_manual_verification(verification_data)

    if success:
        print("SQL injection verification processed successfully")
        print(f"Learning data updated in: {processor.learning_file}")
        print(f"Few-shot examples updated in: {processor.few_shot_file}")
    else:
        print("Failed to process SQL injection verification")


async def demo_xss_false_positive():
    """Demo processing a false positive XSS finding"""
    processor = ManualVerificationProcessor(Path(__file__).parent.parent)

    # Example: False positive XSS that was incorrectly flagged
    verification_data = {
        "vulnerability_id": "AUTO-XSS-FP-20260415-002",
        "session_id": "reconx-elite-session-002",
        "verification_status": "false_positive",
        "confidence_adjustment": -0.3,
        "manual_notes": "XSS alert was false positive. The reflected input was in a JSON response within a properly escaped string, not in DOM context. No actual XSS execution possible.",
        "verified_by": "security_analyst_jane",
        "verified_at": datetime.now().isoformat(),
        "original_confidence": 0.85,  # High confidence false positive
        "adjusted_confidence": 0.1,  # Very low after manual review
        "impact_severity": "none",
        "reproduction_success": False,
        "additional_context": {
            "target": "app.example.com",
            "endpoint": "/api/search",
            "parameter": "query",
            "response_type": "application/json",
            "context": "json_string_value",
            "encoding": "properly_escaped",
        },
    }

    print("\nProcessing XSS false positive verification...")
    success = await processor.process_manual_verification(verification_data)

    if success:
        print("XSS false positive verification processed successfully")
    else:
        print("Failed to process XSS false positive verification")


async def demo_ssrf_missed_detection():
    """Demo processing a missed SSRF vulnerability"""
    processor = ManualVerificationProcessor(Path(__file__).parent.parent)

    # Example: Missed SSRF due to unusual payload pattern
    verification_data = {
        "vulnerability_id": "MANUAL-SSRF-20260415-003",
        "session_id": "reconx-elite-session-003",
        "verification_status": "confirmed",
        "confidence_adjustment": 0.5,
        "manual_notes": "Blind SSRF in image processing endpoint. Automated scan missed this because the payload was encoded in base64 and required specific headers. Manual testing revealed server makes HTTP requests to arbitrary URLs.",
        "verified_by": "security_analyst_mike",
        "verified_at": datetime.now().isoformat(),
        "original_confidence": 0.05,  # Extremely low, completely missed
        "adjusted_confidence": 0.9,  # High confidence after manual verification
        "impact_severity": "high",
        "reproduction_success": True,
        "additional_context": {
            "target": "internal.app.example.com",
            "endpoint": "/api/v2/process-image",
            "parameter": "image_data",
            "payload_encoding": "base64",
            "required_headers": [
                "X-Request-ID: manual-test",
                "Content-Type: application/json",
            ],
            "oast_technique": "burp_collaborator",
            "dns_callback": "received",
            "internal_network_access": True,
        },
    }

    print("\nProcessing SSRF manual verification...")
    success = await processor.process_manual_verification(verification_data)

    if success:
        print("SSRF verification processed successfully")
    else:
        print("Failed to process SSRF verification")


async def show_learning_summary():
    """Display summary of learning data"""
    processor = ManualVerificationProcessor(Path(__file__).parent.parent)

    print("\n" + "=" * 60)
    print("LEARNING SYSTEM SUMMARY")
    print("=" * 60)

    # Load and display learning data
    learning_data = await processor._load_learning_data()
    few_shot_data = await processor._load_few_shot_data()

    print(
        f"Total Verification Results: {learning_data['metadata']['total_verifications']}"
    )
    print(
        f"Total Learning Entries: {learning_data['metadata']['total_learning_entries']}"
    )
    print(f"Total Few-Shot Examples: {few_shot_data['metadata']['total_examples']}")
    print(f"Last Updated: {learning_data['metadata']['last_updated']}")

    # Show verification results
    if learning_data["verification_results"]:
        print("\nVerification Results:")
        for i, result in enumerate(learning_data["verification_results"], 1):
            print(
                f"  {i}. {result['vulnerability_id']} - {result['verification_status']} (Confidence: {result['original_confidence']} -> {result['adjusted_confidence']})"
            )

    # Show learning entries
    if learning_data["learning_entries"]:
        print("\nLearning Entries:")
        for i, entry in enumerate(learning_data["learning_entries"], 1):
            print(f"  {i}. {entry['learning_type']} - {entry['pattern'][:50]}...")

    # Show few-shot examples
    if few_shot_data["few_shot_examples"]:
        print("\nFew-Shot Examples:")
        for i, example in enumerate(few_shot_data["few_shot_examples"], 1):
            print(f"  {i}. {example['module']} - {example['scenario'][:50]}...")


async def main():
    """Main demonstration function"""
    print("ReconX-Elite Manual Verification Processing Demo")
    print("=" * 60)

    # Process different types of manual verifications
    await demo_sql_injection_verification()
    await demo_xss_false_positive()
    await demo_ssrf_missed_detection()

    # Show learning summary
    await show_learning_summary()

    print("\n" + "=" * 60)
    print("Demo completed successfully!")
    print("The learning system has been updated with manual verification data.")
    print("This will improve future AI detection accuracy and consensus thresholds.")


if __name__ == "__main__":
    asyncio.run(main())
