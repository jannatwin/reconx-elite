import unittest
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.services.intelligence import (
    build_subdomain_record,
    extract_endpoints_from_javascript,
    extract_secret_like_strings,
    normalize_and_dedupe_urls,
)


class IntelligenceTests(unittest.TestCase):
    def test_normalize_and_score_endpoint_shape(self):
        rows = normalize_and_dedupe_urls(
            [
                "https://app.example.com/admin/users?id=1&user=2#fragment",
                "https://app.example.com/admin/users?user=9&id=8",
            ],
            source="gau",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["normalized_url"], "https://app.example.com/admin/users?id&user"
        )
        self.assertEqual(rows[0]["priority_score"], 120)

    def test_extracts_only_in_scope_js_endpoints(self):
        js = 'const a="/api/v1/users?id=1"; const b="https://cdn.example.net/lib.js";'
        extracted = extract_endpoints_from_javascript(
            js, "https://app.example.com/static/app.js", {"app.example.com"}
        )
        self.assertEqual(extracted, ["https://app.example.com/api/v1/users?id=1"])

    def test_extract_secret_like_strings_returns_snippets(self):
        secrets = extract_secret_like_strings(
            'const api_key = "ABCDEFGHIJKLMNOP123456";'
        )
        self.assertEqual(secrets[0]["kind"], "api_key")
        self.assertIn("ABCDEFGHIJKLMNOP", secrets[0]["snippet"])

    def test_build_subdomain_record_marks_takeover_candidates(self):
        record = build_subdomain_record(
            "staging.example.com",
            {
                "staging.example.com": {
                    "cname": "dangling.azurewebsites.net",
                    "ip": "1.2.3.4",
                    "tech_stack": [],
                }
            },
            set(),
        )
        self.assertEqual(record["environment"], "staging")
        self.assertTrue(record["takeover_candidate"])


if __name__ == "__main__":
    unittest.main()
