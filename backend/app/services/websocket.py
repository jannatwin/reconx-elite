import json
import logging
from collections import deque
import os
from typing import Dict, List, Set
from enum import Enum

import redis.asyncio as redis
from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User

logger = logging.getLogger(__name__)
_AGENT_LOG_HISTORY: deque[dict] = deque(maxlen=250)
_PROCESS_ID = str(os.getpid())


class NotificationType(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    VULNERABILITY_FOUND = "vulnerability_found"
    CRITICAL_VULNERABILITY = "critical_vulnerability"
    TARGET_ADDED = "target_added"
    SYSTEM_ALERT = "system_alert"
    USER_NOTIFICATION = "user_notification"
    AGENT_LOG = "agent_log"


class WebSocketManager:
    """Manages WebSocket connections for real-time notifications."""

    def __init__(self):
        # Store active connections by user_id
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        self.agent_log_connections: Set[WebSocket] = set()
        # Redis client for cross-process communication
        self.redis_client = None

    async def init_redis(self):
        """Initialize Redis client for pub/sub."""
        if not self.redis_client:
            self.redis_client = redis.from_url(settings.redis_url)

    async def connect(self, websocket: WebSocket, user_id: int):
        """Accept WebSocket connection and register user."""
        await websocket.accept()

        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()

        self.active_connections[user_id].add(websocket)

        # Send welcome message
        await self.send_personal_message(
            user_id,
            {
                "type": NotificationType.USER_NOTIFICATION,
                "data": {
                    "title": "Connected",
                    "message": "Connected to real-time notifications",
                    "notification_type": "info",
                },
                "timestamp": self._get_timestamp(),
            },
        )

        logger.info(f"WebSocket connected for user {user_id}")

    def disconnect(self, websocket: WebSocket, user_id: int):
        """Remove WebSocket connection and cleanup."""
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)

            # Clean up empty user connections
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]

        logger.info(f"WebSocket disconnected for user {user_id}")

    async def send_personal_message(self, user_id: int, message: dict):
        """Send message to specific user."""
        if user_id in self.active_connections:
            disconnected_connections = set()

            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error sending WebSocket message: {e}")
                    disconnected_connections.add(connection)

            # Remove disconnected connections
            for connection in disconnected_connections:
                self.active_connections[user_id].discard(connection)

    async def broadcast_to_all(self, message: dict):
        """Broadcast message to all connected users."""
        disconnected_connections = {}

        for user_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error broadcasting WebSocket message: {e}")
                    if user_id not in disconnected_connections:
                        disconnected_connections[user_id] = set()
                    disconnected_connections[user_id].add(connection)

        # Remove disconnected connections
        for user_id, connections in disconnected_connections.items():
            for connection in connections:
                self.active_connections[user_id].discard(connection)

    async def connect_agent_log(self, websocket: WebSocket):
        await websocket.accept()
        self.agent_log_connections.add(websocket)
        logger.info("Agent log WebSocket connected")

    def disconnect_agent_log(self, websocket: WebSocket):
        self.agent_log_connections.discard(websocket)
        logger.info("Agent log WebSocket disconnected")

    async def broadcast_agent_log(self, message: dict):
        disconnected: set[WebSocket] = set()
        for connection in self.agent_log_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error broadcasting agent log message: {e}")
                disconnected.add(connection)
        for connection in disconnected:
            self.agent_log_connections.discard(connection)

    async def publish_to_redis(self, channel: str, message: dict):
        """Publish message to Redis for cross-process communication."""
        await self.init_redis()
        try:
            await self.redis_client.publish(
                f"reconx:notifications:{channel}", json.dumps(message)
            )
        except Exception as e:
            logger.error(f"Error publishing to Redis: {e}")

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()


# Global WebSocket manager instance
manager = WebSocketManager()


def record_agent_log_event(message: dict):
    _AGENT_LOG_HISTORY.append(message)


def get_recent_agent_log_events(limit: int = 100) -> list[dict]:
    if limit <= 0:
        return []
    return list(_AGENT_LOG_HISTORY)[-limit:]


async def notify_scan_started(user_id: int, target_domain: str, scan_id: int):
    """Send notification when scan starts."""
    message = {
        "type": NotificationType.SCAN_STARTED,
        "user_id": user_id,
        "data": {
            "target_domain": target_domain,
            "scan_id": scan_id,
            "message": f"Scan started for {target_domain}",
        },
        "timestamp": manager._get_timestamp(),
    }

    await manager.send_personal_message(user_id, message)
    await manager.publish_to_redis("scan_events", message)


async def notify_scan_completed(
    user_id: int, target_domain: str, scan_id: int, results: dict
):
    """Send notification when scan completes successfully."""
    message = {
        "type": NotificationType.SCAN_COMPLETED,
        "user_id": user_id,
        "data": {
            "target_domain": target_domain,
            "scan_id": scan_id,
            "results": {
                "subdomains_found": results.get("subdomains_count", 0),
                "vulnerabilities_found": results.get("vulnerabilities_count", 0),
                "endpoints_found": results.get("endpoints_count", 0),
                "attack_paths_found": results.get("attack_paths_count", 0),
            },
            "message": f"Scan completed for {target_domain}",
        },
        "timestamp": manager._get_timestamp(),
    }

    await manager.send_personal_message(user_id, message)
    await manager.publish_to_redis("scan_events", message)


async def notify_scan_failed(
    user_id: int, target_domain: str, scan_id: int, error: str
):
    """Send notification when scan fails."""
    message = {
        "type": NotificationType.SCAN_FAILED,
        "user_id": user_id,
        "data": {
            "target_domain": target_domain,
            "scan_id": scan_id,
            "error": error,
            "message": f"Scan failed for {target_domain}: {error}",
        },
        "timestamp": manager._get_timestamp(),
    }

    await manager.send_personal_message(user_id, message)
    await manager.publish_to_redis("scan_events", message)


async def notify_critical_vulnerability(user_id: int, vulnerability: dict):
    """Send notification for critical vulnerability found."""
    message = {
        "type": NotificationType.CRITICAL_VULNERABILITY,
        "user_id": user_id,
        "data": {
            "vulnerability": {
                "id": vulnerability.get("id"),
                "template_id": vulnerability.get("template_id"),
                "severity": vulnerability.get("severity"),
                "matched_url": vulnerability.get("matched_url"),
                "description": vulnerability.get("description"),
            },
            "message": f"Critical vulnerability found: {vulnerability.get('template_id', 'Unknown')}",
        },
        "timestamp": manager._get_timestamp(),
    }

    await manager.send_personal_message(user_id, message)
    await manager.publish_to_redis("security_alerts", message)


async def notify_system_alert(message: str, severity: str = "info"):
    """Send system-wide alert to all users."""
    notification_message = {
        "type": NotificationType.SYSTEM_ALERT,
        "data": {"message": message, "severity": severity, "title": "System Alert"},
        "timestamp": manager._get_timestamp(),
    }

    await manager.broadcast_to_all(notification_message)
    await manager.publish_to_redis("system_alerts", notification_message)


async def notify_user_notification(
    user_id: int, title: str, message: str, notification_type: str = "info"
):
    """Send custom notification to specific user."""
    notification_message = {
        "type": NotificationType.USER_NOTIFICATION,
        "data": {
            "title": title,
            "message": message,
            "notification_type": notification_type,
        },
        "timestamp": manager._get_timestamp(),
    }

    await manager.send_personal_message(user_id, notification_message)


async def publish_agent_log_event(message: dict):
    payload = {
        "type": NotificationType.AGENT_LOG,
        "data": message | {"origin_process": _PROCESS_ID},
        "timestamp": manager._get_timestamp(),
    }
    record_agent_log_event(payload)
    await manager.broadcast_agent_log(payload)
    await manager.publish_to_redis("agent_log", payload)


class RedisSubscriber:
    """Redis subscriber for cross-process WebSocket notifications."""

    def __init__(self):
        self.redis_client = None
        self.pubsub = None

    async def start(self):
        """Start subscribing to Redis channels."""
        try:
            await manager.init_redis()

            if not manager.redis_client:
                logger.error("Redis client not initialized")
                return

            self.pubsub = manager.redis_client.pubsub()

            await self.pubsub.subscribe(
                "reconx:notifications:scan_events",
                "reconx:notifications:security_alerts",
                "reconx:notifications:system_alerts",
                "reconx:notifications:agent_log",
            )

            logger.info("Redis subscriber started")

            async for message in self.pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        channel = message["channel"]

                        if "scan_events" in channel:
                            await self._handle_scan_event(data)
                        elif "security_alerts" in channel:
                            await self._handle_security_alert(data)
                        elif "system_alerts" in channel:
                            await self._handle_system_alert(data)
                        elif "agent_log" in channel:
                            await self._handle_agent_log(data)

                    except json.JSONDecodeError as e:
                        logger.error(f"Error decoding Redis message: {e}")
                    except Exception as e:
                        logger.error(f"Error handling Redis message: {e}")
        except Exception as e:
            logger.warning("Redis subscriber unavailable: %s", e)

    async def _handle_scan_event(self, data: dict):
        """Handle scan-related events from other processes."""
        user_id = data.get("user_id")
        if user_id:
            await manager.send_personal_message(user_id, data)
        else:
            logger.warning(f"Received scan event without user_id: {data}")

    async def _handle_security_alert(self, data: dict):
        """Handle security alerts from other processes."""
        user_id = data.get("user_id")
        if user_id:
            await manager.send_personal_message(user_id, data)
        else:
            logger.warning(f"Received security alert without user_id: {data}")

    async def _handle_system_alert(self, data: dict):
        """Handle system alerts from other processes."""
        # System alerts are broadcast to all connected users
        await manager.broadcast_to_all(data)

    async def _handle_agent_log(self, data: dict):
        """Handle agent log events from other processes."""
        if (data.get("data") or {}).get("origin_process") == _PROCESS_ID:
            return
        record_agent_log_event(data)
        await manager.broadcast_agent_log(data)

    async def stop(self):
        """Stop the subscriber."""
        if self.pubsub:
            await self.pubsub.unsubscribe()
            await self.pubsub.close()
        logger.info("Redis subscriber stopped")


# Global subscriber instance
redis_subscriber = RedisSubscriber()
