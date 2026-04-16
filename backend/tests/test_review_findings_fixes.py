"""Regression tests for targeted code review fixes."""

import asyncio
import logging
import sys
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from sqlalchemy.sql.elements import TextClause

from app.main import _trusted_hosts_from_origins
from app.core.logging_config import _ReconXJsonFormatter
from app.models.blind_xss_hit import BlindXssHit
from app.routers.admin import system_health
from app.routers.scans import _build_scan_config_from_request
from app.routers.targets import _invalidate_targets_cache
from app.routers.vulnerabilities import _vulnerability_cache_key, _vulnerability_cache_prefix
from app.schemas.scan import ScanConfigRequest
from app.services.blind_xss_service import BlindXssService


class TestReviewFindingFixes(unittest.TestCase):
    def test_blind_xss_record_hit_reuses_token_row(self):
        existing_hit = BlindXssHit(
            user_id=7,
            token="token-123",
            ip_address=BlindXssService.PLACEHOLDER_IP_ADDRESS,
        )
        existing_hit.payload_opportunity_id = 12

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing_hit

        result = BlindXssService.record_hit(
            db=db,
            token="token-123",
            ip_address="203.0.113.10",
            user_agent="test-agent",
            headers={"x-test": "1"},
            cookies={"session": "abc"},
            referrer="https://example.com",
            url_path="https://callback.example/xss/token-123",
            method="POST",
            raw_request="payload=test",
        )

        self.assertIs(result, existing_hit)
        self.assertEqual(existing_hit.ip_address, "203.0.113.10")
        self.assertEqual(existing_hit.method, "POST")
        self.assertEqual(existing_hit.cookies_json, {"session": "abc"})
        db.add.assert_not_called()
        db.commit.assert_called_once()
        db.refresh.assert_called_once_with(existing_hit)

    def test_trusted_hosts_strip_scheme_and_port(self):
        hosts = _trusted_hosts_from_origins(
            [
                "http://localhost:5173",
                "https://app.example.com",
                "127.0.0.1:3000",
                "https://app.example.com",
            ]
        )

        self.assertEqual(hosts, ["localhost", "app.example.com", "127.0.0.1"])

    def test_scan_config_accepts_extended_profile(self):
        payload = ScanConfigRequest(profile="extended")

        cfg = _build_scan_config_from_request(payload)

        self.assertEqual(cfg["profile"], "extended")

    def test_target_cache_invalidation_helper_awaits_invalidate(self):
        with patch("app.routers.targets.invalidate", new=AsyncMock()) as mock_invalidate:
            asyncio.run(_invalidate_targets_cache("reconx:1:targets:"))

        mock_invalidate.assert_awaited_once_with("reconx:1:targets:")

    def test_vulnerability_cache_key_includes_pagination(self):
        page_one = _vulnerability_cache_key(user_id=1, target_id=99, skip=0, limit=50)
        page_two = _vulnerability_cache_key(user_id=1, target_id=99, skip=50, limit=50)
        prefix = _vulnerability_cache_prefix(user_id=1, target_id=99)

        self.assertNotEqual(page_one, page_two)
        self.assertTrue(page_one.startswith(prefix))
        self.assertTrue(page_two.startswith(prefix))

    def test_admin_health_uses_text_clause_for_postgres_probe(self):
        admin = Mock()
        db = Mock()
        fake_redis = Mock()
        fake_redis.ping.return_value = True
        fake_inspect = Mock()
        fake_inspect.stats.return_value = {"worker": {}}
        fake_celery_module = types.ModuleType("app.tasks.celery_app")
        fake_celery_module.celery_app = Mock()
        fake_celery_module.celery_app.control.inspect.return_value = fake_inspect

        with patch("app.routers.admin.redis.from_url", return_value=fake_redis), patch.dict(
            sys.modules,
            {"app.tasks.celery_app": fake_celery_module},
        ):
            result = system_health(admin=admin, db=db)

        statement = db.execute.call_args.args[0]
        self.assertIsInstance(statement, TextClause)
        self.assertEqual(result["postgresql"], "healthy")

    def test_logging_formatter_emits_level_without_key_error(self):
        formatter = _ReconXJsonFormatter(fmt="%(asctime)s %(levelname)s %(name)s %(message)s")
        record = logging.LogRecord(
            name="reconx.api",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello world",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        self.assertIn('"level": "INFO"', output)
        self.assertIn('"logger": "reconx.api"', output)


if __name__ == "__main__":
    unittest.main()
