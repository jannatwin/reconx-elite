"""Unit tests for Gemini scan-response validation and merge helpers."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if "google.generativeai" not in sys.modules:
    _mock_genai = types.ModuleType("google.generativeai")

    def _configure(**_kwargs):
        return None

    class _GenerativeModel:
        def __init__(self, *args, **kwargs):
            pass

        async def generate_content_async(self, *_args, **_kwargs):
            raise RuntimeError("mock: no network in unit tests")

    _mock_genai.configure = _configure
    _mock_genai.GenerativeModel = _GenerativeModel
    sys.modules["google.generativeai"] = _mock_genai

from app.services.ai_service import (
    _merge_high_value_targets_by_url,
    _merge_potential_leaks,
    _validate_ai_scan_response,
    build_javascript_asset_summaries_for_ai,
)


class ValidateAiScanResponseTests(unittest.TestCase):
    def test_preserves_high_value_target_dicts(self):
        raw = {
            "high_value_targets": [
                {"url": "api.example.com", "reason": "staging API", "priority": 9},
                {"url": "evil", "reason": "staging candidate"},
            ],
            "potential_leaks": [{"type": "path", "detail": "/internal/debug"}],
            "juicy_js_files": [
                {
                    "url": "cdn.example.com/app.js",
                    "rationale": "large bundle",
                    "focus_areas": "payments",
                }
            ],
            "suggested_nuclei_templates": ["misconfiguration/http/auth-bypass.yaml"],
            "security_flags": ["x"],
            "confidence_score": "high",
            "malicious_top_level": {"nested": "data"},
        }
        cleaned = _validate_ai_scan_response(raw)
        self.assertNotIn("malicious_top_level", cleaned)
        targets = cleaned.get("high_value_targets") or []
        self.assertEqual(len(targets), 2)
        self.assertIsInstance(targets[0], dict)
        self.assertEqual(targets[0].get("url"), "api.example.com")
        self.assertEqual(targets[0].get("priority"), 9)
        self.assertIn("reason", targets[1])

        leaks = cleaned.get("potential_leaks") or []
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0].get("type"), "path")

        juicy = cleaned.get("juicy_js_files") or []
        self.assertEqual(len(juicy), 1)
        self.assertIn("payments", juicy[0].get("focus_areas", ""))

    def test_priority_clamped(self):
        raw = {"high_value_targets": [{"url": "a.test", "priority": 99}]}
        cleaned = _validate_ai_scan_response(raw)
        self.assertEqual(cleaned["high_value_targets"][0]["priority"], 10)

    def test_non_dict_targets_dropped(self):
        raw = {"high_value_targets": ["not-a-dict", {"url": "ok.test", "priority": 5}]}
        cleaned = _validate_ai_scan_response(raw)
        self.assertEqual(len(cleaned["high_value_targets"]), 1)


class MergeHighValueTargetsTests(unittest.TestCase):
    def test_dedupes_by_url_keeps_higher_priority(self):
        merged = _merge_high_value_targets_by_url(
            [
                {"url": "h.test", "priority": 5},
                {"url": "h.test", "priority": 8},
                {"url": "other.test", "priority": 7},
            ]
        )
        by_url = {t["url"]: t for t in merged}
        self.assertEqual(by_url["h.test"]["priority"], 8)
        self.assertEqual(merged[0]["url"], "h.test")


class MergePotentialLeaksTests(unittest.TestCase):
    def test_dedupes_type_detail(self):
        merged = _merge_potential_leaks(
            [
                {"type": "a", "detail": "same"},
                {"type": "a", "detail": "same"},
                {"type": "b", "detail": "other"},
            ]
        )
        self.assertEqual(len(merged), 2)


class BuildJavaScriptSummariesTests(unittest.TestCase):
    def test_builds_samples_and_counts(self):
        rows = [
            {
                "url": "https://app.example/static/main.js",
                "secrets_json": [{"k": "v"}],
                "extracted_endpoints": [
                    "https://app.example/api/v1/user",
                    "https://app.example/api/v1/user",
                    "https://app.example/internal/x",
                ],
            }
        ]
        summaries = build_javascript_asset_summaries_for_ai(rows)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["secret_count"], 1)
        self.assertEqual(summaries[0]["extracted_endpoint_count"], 3)
        self.assertIn("/api/v1/user", summaries[0]["path_prefix_samples"][0])


if __name__ == "__main__":
    unittest.main()
