import unittest
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.services.domain import normalize_domain


class DomainServiceTests(unittest.TestCase):
    def test_normalizes_valid_domain(self):
        self.assertEqual(normalize_domain("Example.COM"), "example.com")

    def test_accepts_url_and_strips_to_host(self):
        self.assertEqual(normalize_domain("https://example.com"), "example.com")
        self.assertEqual(
            normalize_domain("HTTPS://Example.COM/path?q=1"), "example.com"
        )
        self.assertEqual(normalize_domain("//cdn.example.com/foo"), "cdn.example.com")
        self.assertEqual(normalize_domain("example.com/"), "example.com")

    def test_rejects_invalid_characters(self):
        with self.assertRaises(ValueError):
            normalize_domain("example .com")


if __name__ == "__main__":
    unittest.main()
