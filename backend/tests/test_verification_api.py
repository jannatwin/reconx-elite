import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.deps import get_current_user, require_admin
from app.main import app
from app.schemas.verification import HostGroupState, JavaScriptAnalysisState, VerificationFinding


class VerificationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_secret = settings.jwt_secret_key
        settings.jwt_secret_key = "test-verification-api-secret"

    @classmethod
    def tearDownClass(cls):
        settings.jwt_secret_key = cls._orig_secret

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_state_route_returns_scan_state(self):
        fake_user = SimpleNamespace(id=1, role="admin")
        fake_target = SimpleNamespace(id=7, domain="example.com")
        fake_scan = SimpleNamespace(
            id=11,
            target_id=7,
            status="completed",
            error=None,
            metadata_json={"stage": "completed", "errors": []},
            scan_config_json={"profile": "balanced"},
            vulnerabilities=[],
        )

        app.dependency_overrides[get_current_user] = lambda: fake_user

        with (
            patch("app.routers.verification_api._load_target_and_scan", return_value=(fake_target, fake_scan)),
            patch("app.routers.verification_api._build_findings", return_value=[]),
            patch(
                "app.routers.verification_api._build_host_groups",
                return_value=HostGroupState(total_discovered=12, live=4, api_targets=["api.example.com"]),
            ),
            patch(
                "app.routers.verification_api._build_js_analysis",
                return_value=JavaScriptAnalysisState(files_analyzed=2, endpoints_found=["https://api.example.com/v1"]),
            ),
            patch(
                "app.routers.verification_api._build_chains",
                return_value=[{"title": "Example chain", "combined_severity": "High", "nodes": []}],
            ),
            patch(
                "app.routers.verification_api.get_recent_agent_log_events",
                return_value=[
                    {
                        "type": "agent_log",
                        "timestamp": "2026-04-12T00:00:00Z",
                        "data": {"event": "verification_started", "status": "started", "success": True},
                    }
                ],
            ),
        ):
            client = TestClient(app)
            response = client.get("/api/state?target_id=7")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["session_id"], "target-7-scan-11")
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["hosts"]["api_targets"], ["api.example.com"])
        self.assertEqual(payload["js_analysis"]["files_analyzed"], 2)
        self.assertEqual(payload["current_phase"], "completed")

    def test_findings_route_filters_confirmed_and_reported(self):
        fake_user = SimpleNamespace(id=1, role="admin")
        fake_target = SimpleNamespace(id=7, domain="example.com")
        fake_scan = SimpleNamespace(id=11, target_id=7)

        findings = [
            VerificationFinding(id="1", type="IDOR", endpoint="https://api.example.com", severity="High", status="confirmed"),
            VerificationFinding(id="2", type="XSS", endpoint="https://app.example.com", severity="Medium", status="unconfirmed"),
            VerificationFinding(id="3", type="SSRF", endpoint="https://svc.example.com", severity="Critical", status="reported"),
        ]

        app.dependency_overrides[get_current_user] = lambda: fake_user

        with (
            patch("app.routers.verification_api._load_target_and_scan", return_value=(fake_target, fake_scan)),
            patch("app.routers.verification_api._build_findings", return_value=findings),
        ):
            client = TestClient(app)
            response = client.get("/api/findings?target_id=7")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual({item["status"] for item in payload["findings"]}, {"confirmed", "reported"})

    def test_model_status_requires_admin(self):
        def deny_admin():
            raise HTTPException(status_code=403, detail="Admin role required")

        app.dependency_overrides[require_admin] = deny_admin
        client = TestClient(app)
        response = client.get("/api/model-status")
        self.assertEqual(response.status_code, 403)

    def test_model_status_and_verify_routes(self):
        fake_admin = SimpleNamespace(id=1, role="admin")
        app.dependency_overrides[require_admin] = lambda: fake_admin

        with (
            patch(
                "app.routers.verification_api.get_model_status_snapshot",
                return_value={
                    "provider": "OpenRouter",
                    "models": {"orchestrator": "meta-llama/nemotron-3-nano-30b-a3b"},
                    "statuses": {
                        "orchestrator": {
                            "model": "meta-llama/nemotron-3-nano-30b-a3b",
                            "status": "ONLINE",
                            "response": "ONLINE",
                            "calls_made": 1,
                            "last_verified_at": "2026-04-12T00:00:00Z",
                        }
                    },
                    "updated_at": "2026-04-12T00:00:00Z",
                },
            ),
            patch(
                "app.routers.verification_api.verify_all_models",
                return_value={
                    "orchestrator": {
                        "model": "meta-llama/nemotron-3-nano-30b-a3b",
                        "status": "ONLINE",
                        "response": "ONLINE",
                    }
                },
            ),
        ):
            client = TestClient(app)
            status_response = client.get("/api/model-status")
            verify_response = client.post("/api/verify-models")

        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.json()["statuses"]["orchestrator"]["status"], "ONLINE")
        self.assertEqual(verify_response.status_code, 200)
        self.assertEqual(verify_response.json()["orchestrator"]["status"], "ONLINE")


if __name__ == "__main__":
    unittest.main()
