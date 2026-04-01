"""SSRF detection service for managing tokens and signal recording."""

import secrets
from typing import Optional

from sqlalchemy.orm import Session

from app.models.ssrf_signal import SsrfSignal


class SsrfService:
    """Service for SSRF detection and signal management."""

    @staticmethod
    def generate_unique_token() -> str:
        """Generate a unique token for SSRF detection."""
        return secrets.token_hex(32)

    @staticmethod
    def create_token_for_opportunity(db: Session, user_id: int, opportunity_id: Optional[int] = None) -> str:
        """Create a new SSRF token for a user and opportunity."""
        token = SsrfService.generate_unique_token()

        # Create the token entry
        signal = SsrfSignal(
            user_id=user_id,
            token=token,
            payload_opportunity_id=opportunity_id,
            signal_type="pending",  # Will be updated when triggered
        )

        db.add(signal)
        db.commit()

        return token

    @staticmethod
    def record_signal(
        db: Session,
        token: str,
        signal_type: str,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        ip_address: str = "unknown",
        user_agent: Optional[str] = None,
        headers: Optional[dict] = None,
        raw_request: Optional[str] = None,
        referrer: Optional[str] = None,
        url_path: Optional[str] = None,
        method: str = "GET",
    ) -> bool:
        """
        Record an SSRF signal when a callback is triggered.

        Returns True if signal was recorded, False if token not found.
        """
        # Find the token entry
        signal = db.query(SsrfSignal).filter(SsrfSignal.token == token).first()
        if not signal:
            return False

        # Update the signal with detection details
        signal.signal_type = signal_type
        signal.target_host = target_host
        signal.target_port = target_port
        signal.ip_address = ip_address
        signal.user_agent = user_agent
        signal.headers_json = headers or {}
        signal.raw_request = raw_request
        signal.referrer = referrer
        signal.url_path = url_path
        signal.method = method
        signal.processed = 1  # Mark as processed

        db.commit()
        return True

    @staticmethod
    def create_payload_with_token(payload_template: str, token: str, domain: str) -> str:
        """Replace placeholders in payload template with actual token and domain."""
        payload = payload_template.replace("__TOKEN__", token)
        payload = payload.replace("yourdomain.com", domain)
        return payload