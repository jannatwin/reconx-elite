"""
Notification Hub - Real-time Alert System
Supports Telegram and Discord webhooks for critical events
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

import aiofiles
import httpx

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    NEW_SUBDOMAIN = "new_subdomain"
    VALID_POC = "valid_poc"
    MONITORING_ERROR = "monitoring_error"
    SCAN_COMPLETED = "scan_completed"
    CRITICAL_VULNERABILITY = "critical_vulnerability"
    MASS_SCAN_COMPLETED = "mass_scan_completed"
    CONSENSUS_ALERT = "consensus_alert"


class PlatformType(Enum):
    TELEGRAM = "telegram"
    DISCORD = "discord"


@dataclass
class NotificationMessage:
    title: str
    message: str
    severity: str
    timestamp: str
    metadata: Dict[str, Any]
    platform: PlatformType
    webhook_url: str


@dataclass
class NotificationConfig:
    telegram_enabled: bool
    discord_enabled: bool
    telegram_webhook_url: str
    discord_webhook_url: str
    rate_limit_seconds: int
    max_retries: int
    timeout_seconds: int


class NotificationHub:
    """Real-time notification system with multi-platform support"""

    def __init__(self, session_id: str):
        self.session_id = session_id

        # Load configuration
        self.config = self._load_config()

        # Rate limiting
        self.last_notifications = {}
        self.notification_queue = asyncio.Queue()

        # HTTP client
        self.http_client = httpx.AsyncClient(timeout=self.config.timeout_seconds)

        # Platform-specific formatters
        self.formatters = {
            PlatformType.TELEGRAM: self._format_telegram_message,
            PlatformType.DISCORD: self._format_discord_message,
        }

    def _load_config(self) -> NotificationConfig:
        """Load notification configuration from environment"""
        return NotificationConfig(
            telegram_enabled=os.getenv(
                "TELEGRAM_NOTIFICATIONS_ENABLED", "false"
            ).lower()
            == "true",
            discord_enabled=os.getenv("DISCORD_NOTIFICATIONS_ENABLED", "false").lower()
            == "true",
            telegram_webhook_url=os.getenv("TELEGRAM_WEBHOOK_URL", ""),
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", ""),
            rate_limit_seconds=int(os.getenv("NOTIFICATION_RATE_LIMIT_SECONDS", "30")),
            max_retries=int(os.getenv("NOTIFICATION_MAX_RETRIES", "3")),
            timeout_seconds=int(os.getenv("NOTIFICATION_TIMEOUT_SECONDS", "30")),
        )

    async def send_notification(
        self,
        notification_type: NotificationType,
        title: str,
        message: str,
        severity: str = "info",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send notification to all enabled platforms"""
        if metadata is None:
            metadata = {}

        # Check rate limiting
        if not self._check_rate_limit(notification_type):
            logger.debug(f"Notification rate limited: {notification_type.value}")
            return False

        # Create notification messages
        messages = []
        timestamp = datetime.now().isoformat()

        if self.config.telegram_enabled and self.config.telegram_webhook_url:
            telegram_msg = NotificationMessage(
                title=title,
                message=message,
                severity=severity,
                timestamp=timestamp,
                metadata=metadata,
                platform=PlatformType.TELEGRAM,
                webhook_url=self.config.telegram_webhook_url,
            )
            messages.append(telegram_msg)

        if self.config.discord_enabled and self.config.discord_webhook_url:
            discord_msg = NotificationMessage(
                title=title,
                message=message,
                severity=severity,
                timestamp=timestamp,
                metadata=metadata,
                platform=PlatformType.DISCORD,
                webhook_url=self.config.discord_webhook_url,
            )
            messages.append(discord_msg)

        if not messages:
            logger.debug("No notification platforms enabled")
            return False

        # Send notifications
        success_count = 0
        for notification_msg in messages:
            try:
                if await self._send_single_notification(notification_msg):
                    success_count += 1
            except Exception as e:
                logger.error(
                    f"Failed to send {notification_msg.platform.value} notification: {e}"
                )

        return success_count > 0

    async def _send_single_notification(
        self, notification_msg: NotificationMessage
    ) -> bool:
        """Send a single notification to a platform"""
        # Format message for platform
        formatted_message = self.formatters[notification_msg.platform](notification_msg)

        # Prepare payload
        if notification_msg.platform == PlatformType.TELEGRAM:
            payload = self._prepare_telegram_payload(formatted_message)
        else:  # Discord
            payload = self._prepare_discord_payload(formatted_message)

        # Send with retries
        for attempt in range(self.config.max_retries):
            try:
                response = await self.http_client.post(
                    notification_msg.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    logger.info(
                        f"Notification sent to {notification_msg.platform.value}"
                    )
                    return True
                else:
                    logger.warning(
                        f"Failed to send {notification_msg.platform.value} notification: {response.status_code}"
                    )

            except Exception as e:
                logger.warning(
                    f"Attempt {attempt + 1} failed for {notification_msg.platform.value}: {e}"
                )
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2**attempt)  # Exponential backoff

        return False

    def _check_rate_limit(self, notification_type: NotificationType) -> bool:
        """Check if notification is rate limited"""
        current_time = datetime.now().timestamp()
        last_time = self.last_notifications.get(notification_type.value, 0)

        if current_time - last_time < self.config.rate_limit_seconds:
            return False

        self.last_notifications[notification_type.value] = current_time
        return True

    def _format_telegram_message(self, notification_msg: NotificationMessage) -> str:
        """Format message for Telegram"""
        # Telegram supports Markdown formatting
        severity_emoji = {
            "critical": "??",
            "high": "?",
            "medium": "?",
            "low": "?",
            "info": "?",
        }

        emoji = severity_emoji.get(notification_msg.severity.lower(), "?")

        message = f"{emoji} *{notification_msg.title}*\n\n"
        message += f"{notification_msg.message}\n\n"

        # Add metadata if present
        if notification_msg.metadata:
            for key, value in notification_msg.metadata.items():
                message += f"**{key.replace('_', ' ').title()}:** {value}\n"

        message += f"\n*Timestamp:* {notification_msg.timestamp}"

        return message

    def _format_discord_message(self, notification_msg: NotificationMessage) -> str:
        """Format message for Discord"""
        # Discord supports embeds, but we'll use simple text for compatibility
        severity_emoji = {
            "critical": "??",
            "high": "?",
            "medium": "?",
            "low": "?",
            "info": "?",
        }

        emoji = severity_emoji.get(notification_msg.severity.lower(), "?")

        message = f"{emoji} **{notification_msg.title}**\n\n"
        message += f"{notification_msg.message}\n\n"

        # Add metadata if present
        if notification_msg.metadata:
            for key, value in notification_msg.metadata.items():
                message += f"**{key.replace('_', ' ').title()}:** {value}\n"

        message += f"\n*Timestamp:* {notification_msg.timestamp}"

        return message

    def _prepare_telegram_payload(self, message: str) -> Dict[str, Any]:
        """Prepare payload for Telegram webhook"""
        return {
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

    def _prepare_discord_payload(self, message: str) -> Dict[str, Any]:
        """Prepare payload for Discord webhook"""
        return {
            "content": message,
            "username": "ReconX-Elite",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",  # Replace with actual avatar URL
        }

    # Specific notification methods

    async def notify_new_subdomain(
        self, subdomain: str, target: str, metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send notification for new subdomain discovery"""
        if metadata is None:
            metadata = {}

        title = "New Subdomain Discovered"
        message = f"New subdomain found: `{subdomain}` for target `{target}`"

        # Add additional metadata
        metadata.update(
            {
                "domain": subdomain,
                "target": target,
                "discovery_method": metadata.get("discovery_method", "unknown"),
                "confidence": metadata.get("confidence", "unknown"),
            }
        )

        return await self.send_notification(
            NotificationType.NEW_SUBDOMAIN, title, message, "info", metadata
        )

    async def notify_valid_poc(
        self, vulnerability_id: str, severity: str, endpoint: str, payload: str
    ) -> bool:
        """Send notification for valid proof of concept generation"""
        title = "Valid Proof of Concept Generated"
        message = f"Valid PoC generated for vulnerability `{vulnerability_id}`\n\n"
        message += f"**Endpoint:** `{endpoint}`\n"
        message += f"**Severity:** `{severity}`\n"
        message += f"**Payload:** ```{payload}```"

        metadata = {
            "vulnerability_id": vulnerability_id,
            "severity": severity,
            "endpoint": endpoint,
            "payload": payload,
        }

        return await self.send_notification(
            NotificationType.VALID_POC, title, message, severity.lower(), metadata
        )

    async def notify_monitoring_error(
        self, error_message: str, target: str, error_type: str = "general"
    ) -> bool:
        """Send notification for monitoring loop errors"""
        title = "Monitoring Loop Error"
        message = f"Monitoring error detected for target `{target}`\n\n"
        message += f"**Error Type:** `{error_type}`\n"
        message += f"**Error:** `{error_message}`"

        metadata = {
            "target": target,
            "error_type": error_type,
            "error_message": error_message,
            "timestamp": datetime.now().isoformat(),
        }

        return await self.send_notification(
            NotificationType.MONITORING_ERROR, title, message, "high", metadata
        )

    async def notify_scan_completed(
        self,
        target: str,
        total_vulnerabilities: int,
        critical_count: int,
        high_count: int,
        duration: str,
    ) -> bool:
        """Send notification for scan completion"""
        title = "Scan Completed"
        message = f"Scan completed for target `{target}`\n\n"
        message += f"**Total Vulnerabilities:** `{total_vulnerabilities}`\n"
        message += f"**Critical:** `{critical_count}`\n"
        message += f"**High:** `{high_count}`\n"
        message += f"**Duration:** `{duration}`"

        metadata = {
            "target": target,
            "total_vulnerabilities": total_vulnerabilities,
            "critical_count": critical_count,
            "high_count": high_count,
            "duration": duration,
        }

        # Determine severity based on critical findings
        severity = (
            "critical"
            if critical_count > 0
            else "info" if total_vulnerabilities > 0 else "info"
        )

        return await self.send_notification(
            NotificationType.SCAN_COMPLETED, title, message, severity, metadata
        )

    async def notify_critical_vulnerability(
        self, vulnerability_id: str, severity: str, endpoint: str, description: str
    ) -> bool:
        """Send notification for critical vulnerability discovery"""
        title = "Critical Vulnerability Discovered"
        message = f"Critical vulnerability found: `{vulnerability_id}`\n\n"
        message += f"**Endpoint:** `{endpoint}`\n"
        message += f"**Severity:** `{severity}`\n"
        message += f"**Description:** {description}"

        metadata = {
            "vulnerability_id": vulnerability_id,
            "severity": severity,
            "endpoint": endpoint,
            "description": description,
        }

        return await self.send_notification(
            NotificationType.CRITICAL_VULNERABILITY,
            title,
            message,
            "critical",
            metadata,
        )

    async def notify_mass_scan_completed(
        self,
        targets_count: int,
        templates_count: int,
        total_findings: int,
        duration: str,
    ) -> bool:
        """Send notification for mass scan completion"""
        title = "Mass Scan Completed"
        message = f"Mass scan completed successfully\n\n"
        message += f"**Targets Scanned:** `{targets_count}`\n"
        message += f"**Templates Used:** `{templates_count}`\n"
        message += f"**Total Findings:** `{total_findings}`\n"
        message += f"**Duration:** `{duration}`"

        metadata = {
            "targets_count": targets_count,
            "templates_count": templates_count,
            "total_findings": total_findings,
            "duration": duration,
        }

        # Determine severity based on findings
        severity = "high" if total_findings > 0 else "info"

        return await self.send_notification(
            NotificationType.MASS_SCAN_COMPLETED, title, message, severity, metadata
        )

    async def notify_consensus_alert(
        self,
        vulnerability_id: str,
        consensus_score: float,
        determination: str,
        reasoning: str,
    ) -> bool:
        """Send notification for consensus analysis results"""
        title = "Consensus Analysis Alert"
        message = f"Consensus analysis completed for `{vulnerability_id}`\n\n"
        message += f"**Consensus Score:** `{consensus_score:.2f}`\n"
        message += f"**Determination:** `{determination}`\n"
        message += f"**Reasoning:** {reasoning}"

        metadata = {
            "vulnerability_id": vulnerability_id,
            "consensus_score": consensus_score,
            "determination": determination,
            "reasoning": reasoning,
        }

        # Determine severity based on determination
        severity = "high" if determination == "fail" else "info"

        return await self.send_notification(
            NotificationType.CONSENSUS_ALERT, title, message, severity, metadata
        )

    async def test_notifications(self) -> Dict[str, bool]:
        """Test notification connectivity"""
        results = {}

        # Test Telegram
        if self.config.telegram_enabled:
            telegram_result = await self.send_notification(
                NotificationType.SCAN_COMPLETED,
                "Test Notification",
                "This is a test notification from ReconX-Elite",
                "info",
                {"test": True},
            )
            results["telegram"] = telegram_result
        else:
            results["telegram"] = False

        # Test Discord
        if self.config.discord_enabled:
            discord_result = await self.send_notification(
                NotificationType.SCAN_COMPLETED,
                "Test Notification",
                "This is a test notification from ReconX-Elite",
                "info",
                {"test": True},
            )
            results["discord"] = discord_result
        else:
            results["discord"] = False

        return results

    async def close(self):
        """Close HTTP client"""
        await self.http_client.aclose()
