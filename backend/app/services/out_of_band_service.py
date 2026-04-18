"""Out-of-Band Interaction Service for SSRF and Blind XSS tracking.

Generates unique callback URLs and tracks interactions for vulnerability confirmation.
"""

import hashlib
import json
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.out_of_band_interaction import OutOfBandInteraction
from app.models.user import User

logger = logging.getLogger(__name__)


class OutOfBandService:
    """Service for managing out-of-band interactions."""

    def __init__(self):
        self.base_callback_url = settings.callback_url or "http://localhost:8000"

    def _oob_callback_url(self, callback_id: str) -> str:
        base = self.base_callback_url.rstrip("/")
        return f"{base}/oob/callback/{callback_id}"

    def generate_callback(
        self,
        user_id: int,
        interaction_type: str,
        scan_id: Optional[int] = None,
        vulnerability_id: Optional[int] = None,
    ) -> Dict[str, str]:
        """Generate a unique callback URL for tracking interactions.

        Args:
            user_id: User ID requesting the callback
            interaction_type: Type of interaction (ssrf, blind_xss, dns)
            scan_id: Optional scan ID
            vulnerability_id: Optional vulnerability ID

        Returns:
            Dictionary with callback details
        """
        # Generate unique callback ID
        callback_id = self._generate_callback_id(user_id, interaction_type)

        callback_url = self._oob_callback_url(callback_id)

        # Generate payload-specific URLs
        payloads = self._generate_payloads(callback_id, interaction_type)

        return {
            "callback_id": callback_id,
            "callback_url": callback_url,
            "interaction_type": interaction_type,
            "payloads": payloads,
        }

    def _generate_callback_id(self, user_id: int, interaction_type: str) -> str:
        """Generate a unique callback ID."""
        timestamp = datetime.now(timezone.utc).timestamp()
        random_part = secrets.token_urlsafe(16)

        # Create hash for uniqueness and obfuscation
        hash_input = f"{user_id}:{interaction_type}:{timestamp}:{random_part}"
        callback_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        return f"{interaction_type}_{callback_hash}"

    def _generate_payloads(self, callback_id: str, interaction_type: str) -> List[str]:
        """Generate payloads for different interaction types."""
        payloads = []

        if interaction_type == "ssrf":
            # SSRF payloads
            callback_url = self._oob_callback_url(callback_id)
            payloads.extend(
                [
                    f"http://127.0.0.1/callback/{callback_id}",
                    f"https://127.0.0.1/callback/{callback_id}",
                    f"http://localhost/callback/{callback_id}",
                    callback_url,
                    f"file:///etc/passwd&callback={callback_url}",
                ]
            )

        elif interaction_type == "blind_xss":
            # Blind XSS payloads
            callback_url = self._oob_callback_url(callback_id)
            payloads.extend(
                [
                    f"<img src=x onerror=fetch('{callback_url}')>",
                    f"<script>fetch('{callback_url}')</script>",
                    f"<iframe src='{callback_url}'></iframe>",
                    f"<svg onload=fetch('{callback_url}')>",
                    f"'><script>fetch('{callback_url}')</script>",
                ]
            )

        elif interaction_type == "dns":
            # DNS payloads (if DNS callback is configured)
            dns_domain = getattr(settings, "dns_callback_domain", None)
            if dns_domain:
                payloads.extend(
                    [
                        f"{callback_id}.{dns_domain}",
                        f"test.{callback_id}.{dns_domain}",
                    ]
                )

        return payloads

    def create_callback_record(
        self,
        db: Session,
        user_id: int,
        callback_id: str,
        interaction_type: str,
        scan_id: Optional[int] = None,
        vulnerability_id: Optional[int] = None,
    ) -> OutOfBandInteraction:
        """Create a callback record in the database."""
        callback_url = self._oob_callback_url(callback_id)

        interaction = OutOfBandInteraction(
            user_id=user_id,
            scan_id=scan_id,
            vulnerability_id=vulnerability_id,
            callback_id=callback_id,
            callback_url=callback_url,
            interaction_type=interaction_type,
        )

        db.add(interaction)
        db.commit()
        db.refresh(interaction)

        return interaction

    def record_interaction(
        self, db: Session, callback_id: str, request_data: Dict
    ) -> Optional[OutOfBandInteraction]:
        """Record an incoming callback interaction.

        Args:
            db: Database session
            callback_id: Callback identifier
            request_data: Request details

        Returns:
            Updated interaction record or None if not found
        """
        # Find the callback record
        interaction = (
            db.query(OutOfBandInteraction)
            .filter(OutOfBandInteraction.callback_id == callback_id)
            .first()
        )

        if not interaction:
            logger.warning(f"Callback ID {callback_id} not found")
            return None

        # Update interaction details
        interaction.timestamp = datetime.now(timezone.utc)
        interaction.source_ip = request_data.get("source_ip")
        interaction.user_agent = request_data.get("user_agent")
        interaction.headers = json.dumps(request_data.get("headers", {}))
        interaction.body = request_data.get("body", "")[:1000]  # Limit size
        interaction.method = request_data.get("method")
        interaction.path = request_data.get("path")
        interaction.query_string = request_data.get("query_string")

        # Analyze and confirm interaction
        confidence, notes = self._analyze_interaction(interaction, request_data)
        interaction.confidence_score = confidence
        interaction.analysis_notes = notes
        interaction.is_confirmed = confidence in ["medium", "high"]

        db.commit()
        db.refresh(interaction)

        logger.info(
            f"Recorded {interaction.interaction_type} interaction for callback {callback_id}"
        )

        return interaction

    def _analyze_interaction(
        self, interaction: OutOfBandInteraction, request_data: Dict
    ) -> Tuple[str, str]:
        """Analyze interaction to determine confidence and extract insights."""
        confidence = "low"
        notes = ""

        # Check source IP
        source_ip = request_data.get("source_ip", "")
        if source_ip and not self._is_private_ip(source_ip):
            confidence = "medium"
            notes += f"External IP: {source_ip}"
        elif source_ip and self._is_private_ip(source_ip):
            confidence = "high"
            notes += f"Internal IP: {source_ip} (SSRF confirmed)"

        # Check user agent for automation
        user_agent = request_data.get("user_agent", "")
        if user_agent:
            if any(
                tool in user_agent.lower()
                for tool in ["curl", "wget", "python", "java"]
            ):
                notes += f" [Tool detected: {user_agent[:50]}]"
                if confidence == "low":
                    confidence = "medium"

        # Check for specific patterns
        body = request_data.get("body", "")
        if body:
            if "callback" in body.lower() or interaction.callback_id in body:
                notes += " [Callback reference in body]"
                if confidence == "medium":
                    confidence = "high"

        # Interaction type specific analysis
        if interaction.interaction_type == "ssrf":
            if self._is_private_ip(source_ip):
                confidence = "high"
                notes += " [SSRF to internal network confirmed]"

        elif interaction.interaction_type == "blind_xss":
            if "text/html" in str(request_data.get("headers", {})):
                notes += " [HTML context - likely XSS]"
                confidence = "medium"

        return confidence, notes

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private/internal."""
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except:
            return False

    def get_user_interactions(
        self, db: Session, user_id: int, limit: int = 100
    ) -> List[OutOfBandInteraction]:
        """Get all interactions for a user."""
        return (
            db.query(OutOfBandInteraction)
            .filter(OutOfBandInteraction.user_id == user_id)
            .order_by(OutOfBandInteraction.timestamp.desc())
            .limit(limit)
            .all()
        )

    def get_scan_interactions(
        self, db: Session, scan_id: int
    ) -> List[OutOfBandInteraction]:
        """Get all interactions for a scan."""
        return (
            db.query(OutOfBandInteraction)
            .filter(OutOfBandInteraction.scan_id == scan_id)
            .order_by(OutOfBandInteraction.timestamp.desc())
            .all()
        )

    def get_confirmed_interactions(
        self, db: Session, user_id: int
    ) -> List[OutOfBandInteraction]:
        """Get confirmed interactions for a user."""
        return (
            db.query(OutOfBandInteraction)
            .filter(
                OutOfBandInteraction.user_id == user_id,
                OutOfBandInteraction.is_confirmed == True,
            )
            .order_by(OutOfBandInteraction.timestamp.desc())
            .all()
        )


# Global service instance
oob_service = OutOfBandService()
