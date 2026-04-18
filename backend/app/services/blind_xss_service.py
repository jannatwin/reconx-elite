"""Blind XSS tracking and token management service."""

import secrets
from typing import Optional

from sqlalchemy.orm import Session

from app.models.blind_xss_hit import BlindXssHit


class BlindXssService:
    """Service for managing blind XSS tokens and hits."""

    PLACEHOLDER_IP_ADDRESS = "0.0.0.0"

    @staticmethod
    def generate_unique_token() -> str:
        """Generate a unique 32-character token for blind XSS tracking."""
        return secrets.token_hex(16)  # 32 characters

    @staticmethod
    def create_payload_with_token(
        base_payload: str, token: str, domain: str = "yourdomain.com"
    ) -> str:
        """Replace __TOKEN__ placeholder in payload with actual token and domain."""
        return base_payload.replace("__TOKEN__", f"{domain}/xss/{token}")

    @staticmethod
    def record_hit(
        db: Session,
        token: str,
        ip_address: str,
        user_agent: Optional[str] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        referrer: Optional[str] = None,
        url_path: Optional[str] = None,
        method: str = "GET",
        raw_request: Optional[str] = None,
    ) -> Optional[BlindXssHit]:
        """Record a blind XSS hit in the database."""

        hit = db.query(BlindXssHit).filter(BlindXssHit.token == token).first()
        if not hit:
            return None  # Token not found

        # Reuse the token registration row so callbacks do not violate the unique token constraint.
        hit.ip_address = ip_address
        hit.user_agent = user_agent
        hit.headers_json = headers or {}
        hit.cookies_json = cookies or {}
        hit.referrer = referrer
        hit.url_path = url_path
        hit.method = method
        hit.raw_request = raw_request
        hit.processed = 0
        db.commit()
        db.refresh(hit)

        return hit

    @staticmethod
    def get_user_hits(db: Session, user_id: int, limit: int = 100) -> list[BlindXssHit]:
        """Get all blind XSS hits for a user."""
        return (
            db.query(BlindXssHit)
            .filter(
                BlindXssHit.user_id == user_id,
                BlindXssHit.ip_address != BlindXssService.PLACEHOLDER_IP_ADDRESS,
            )
            .order_by(BlindXssHit.triggered_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_unprocessed_hits(db: Session, user_id: int) -> list[BlindXssHit]:
        """Get unprocessed blind XSS hits for a user."""
        return (
            db.query(BlindXssHit)
            .filter(
                BlindXssHit.user_id == user_id,
                BlindXssHit.processed == 0,
                BlindXssHit.ip_address != BlindXssService.PLACEHOLDER_IP_ADDRESS,
            )
            .order_by(BlindXssHit.triggered_at.desc())
            .all()
        )

    @staticmethod
    def mark_hit_processed(db: Session, hit_id: int, processed_status: int = 1) -> bool:
        """Mark a hit as processed (1) or ignored (2)."""
        hit = db.query(BlindXssHit).filter(BlindXssHit.id == hit_id).first()
        if hit:
            hit.processed = processed_status
            db.commit()
            return True
        return False

    @staticmethod
    def create_token_for_opportunity(
        db: Session, user_id: int, payload_opportunity_id: Optional[int] = None
    ) -> str:
        """Create a new token entry for tracking blind XSS hits."""
        token = BlindXssService.generate_unique_token()

        # Create the token entry
        token_entry = BlindXssHit(
            user_id=user_id,
            token=token,
            payload_opportunity_id=payload_opportunity_id,
            ip_address=BlindXssService.PLACEHOLDER_IP_ADDRESS,
            processed=0,
        )

        db.add(token_entry)
        db.commit()

        return token
