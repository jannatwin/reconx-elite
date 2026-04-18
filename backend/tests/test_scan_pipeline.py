import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.passive_dns import fetch_crtsh_subdomains, normalize_passive_hosts
from app.services.scan_pipeline import pipeline_stage_total, resolve_pipeline_stages


class ScanPipelineTests(unittest.TestCase):
    def test_standard_pipeline_no_modules(self):
        self.assertEqual(
            resolve_pipeline_stages({}), ["subfinder", "httpx", "gau", "nuclei"]
        )
        self.assertEqual(pipeline_stage_total({}), 4)

    def test_extended_passive_prefix(self):
        cfg = {"modules": {"passive_dns": {"crtsh_enabled": True}}}
        stages = resolve_pipeline_stages(cfg)
        self.assertEqual(stages[0], "passive_dns")
        self.assertEqual(stages[1], "subfinder")
        self.assertEqual(stages[-1], "nuclei")

    def test_normalize_passive_hosts(self):
        root = "example.com"
        raw = ["WWW.EXAMPLE.COM", "*.example.com", "evil.org", ""]
        out = normalize_passive_hosts(raw, root)
        self.assertIn("www.example.com", out)
        self.assertNotIn("evil.org", out)

    def test_fetch_crtsh_empty_on_error(self):
        with patch("app.services.passive_dns.httpx.Client") as m:
            m.return_value.__enter__.return_value.get.side_effect = OSError("network")
            self.assertEqual(fetch_crtsh_subdomains("example.com"), [])


if __name__ == "__main__":
    unittest.main()
