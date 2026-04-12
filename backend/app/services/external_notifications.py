"""External notification service for Slack, Discord, and Telegram."""

import json
import logging
import httpx
from typing import Any, Dict, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

class ExternalNotificationService:
    """Service to send notifications to external platforms."""

    async def send_slack_notification(self, webhook_url: str, message: str, title: str = "ReconX Elite Alert"):
        """Send a notification to Slack."""
        if not webhook_url:
            return

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": title,
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload)
                response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

    async def send_discord_notification(self, webhook_url: str, message: str, title: str = "ReconX Elite Alert"):
        """Send a notification to Discord."""
        if not webhook_url:
            return

        payload = {
            "embeds": [
                {
                    "title": title,
                    "description": message,
                    "color": 0x00ff00 if "Success" in title else 0xff0000,
                    "footer": {
                        "text": "ReconX Elite - Automated Security Intelligence"
                    }
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload)
                response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")

    async def notify_critical_finding(self, vulnerability_data: Dict[str, Any]):
        """Send urgent notifications for critical findings."""
        
        severity = vulnerability_data.get("severity", "unknown").upper()
        if severity not in ["HIGH", "CRITICAL"]:
            return

        title = f"🚨 {severity} Finding: {vulnerability_data.get('template_id', 'Unknown')}"
        message = (
            f"*Target*: {vulnerability_data.get('matched_url', 'N/A')}\n"
            f"*Description*: {vulnerability_data.get('description', 'No description provided')}\n"
            f"*Source*: ReconX Elite Automated Scan"
        )

        # Check for configured webhooks in settings (if we add them later)
        # For now, we'll use env vars if they exist
        slack_webhook = getattr(settings, "slack_webhook_url", None)
        discord_webhook = getattr(settings, "discord_webhook_url", None)

        if slack_webhook:
            await self.send_slack_notification(slack_webhook, message, title)
        
        if discord_webhook:
            await self.send_discord_notification(discord_webhook, message, title)

notification_service = ExternalNotificationService()
