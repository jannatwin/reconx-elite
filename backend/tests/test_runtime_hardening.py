import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from starlette.requests import Request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.middleware import AuthGuardMiddleware
from app.core.security import decode_token
from app.services.scan_runner import run_gau
from app.services.tool_executor import ToolExecutionResult


class RuntimeHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_middleware_returns_401_for_value_error(self):
        middleware = AuthGuardMiddleware(app=Mock())
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/scan/1",
            "headers": [(b"authorization", b"Bearer bad-token")],
            "client": ("127.0.0.1", 5000),
        }
        request = Request(scope)

        async def call_next(_request):
            return Mock(status_code=200)

        with patch(
            "app.core.middleware.decode_token", side_effect=ValueError("bad token")
        ):
            response = await middleware.dispatch(request, call_next)
        self.assertEqual(response.status_code, 401)

    def test_decode_token_error_message_is_sanitized(self):
        with self.assertRaises(ValueError) as exc:
            decode_token("not-a-valid-token")
        self.assertNotIn("Signature verification failed", str(exc.exception))

    @patch("app.services.scan_runner.execute_with_retry")
    def test_run_gau_accepts_host_list(self, mock_execute):
        mock_execute.return_value = ToolExecutionResult(
            tool="gau",
            command=["gau", "--subs"],
            status="success",
            attempts=1,
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            return_code=0,
            stdout="https://example.com\n",
            stderr="",
            error=None,
        )
        urls, _ = run_gau(["app.example.com", "api.example.com"])
        self.assertIn("https://example.com", urls)
        self.assertEqual(
            mock_execute.call_args.kwargs["stdin_payload"],
            "app.example.com\napi.example.com\n",
        )


if __name__ == "__main__":
    unittest.main()
