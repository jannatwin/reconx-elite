import json
import logging
from typing import Dict

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import decode_token
from app.models.user import User
from app.services.websocket import manager, redis_subscriber
from app.services.audit import log_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["websocket"])


def _extract_websocket_token(websocket: WebSocket) -> str | None:
    token = websocket.query_params.get("token")
    auth_header = websocket.headers.get("authorization", "")
    if not token and auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    return token


@router.websocket("/{user_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    user_id: int,
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time notifications.
    Clients connect to ws://localhost:8000/ws/{user_id}
    """
    # Validate JWT and bind socket identity to token subject.
    token = _extract_websocket_token(websocket)
    if not token:
        await websocket.close(code=4401, reason="Missing authentication token")
        return
    try:
        claims = decode_token(token)
        if claims.get("token_type") != "access" or int(claims.get("sub")) != user_id:
            await websocket.close(code=4403, reason="Forbidden")
            return
    except (ValueError, TypeError):
        await websocket.close(code=4401, reason="Invalid token")
        return

    # Verify user exists and is valid
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        await websocket.close(code=4004, reason="User not found")
        return
    
    # Accept the connection
    await manager.connect(websocket, user_id)
    
    # Log the connection
    log_audit_event(
        db,
        action="websocket_connected",
        user_id=user_id,
        ip_address=websocket.client.host if websocket.client else None,
        metadata_json={"user_agent": websocket.headers.get("user-agent", "unknown")}
    )
    db.commit()
    
    try:
        # Keep the connection alive and handle incoming messages
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                # Handle different message types from client
                if message.get("type") == "ping":
                    # Respond to ping with pong
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "timestamp": manager._get_timestamp()
                    }))
                elif message.get("type") == "subscribe":
                    # Handle subscription to specific notification types
                    await handle_subscription(websocket, user_id, message.get("channels", []))
                else:
                    logger.warning(f"Unknown message type from WebSocket: {message.get('type')}")
                    
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON received from WebSocket: {data}")
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Invalid JSON format"
                }))
                
    except WebSocketDisconnect:
        # Handle disconnection
        manager.disconnect(websocket, user_id)
        
        # Log the disconnection
        log_audit_event(
            db,
            action="websocket_disconnected",
            user_id=user_id,
            ip_address=websocket.client.host if websocket.client else None,
            metadata_json={"reason": "client_disconnect"}
        )
        db.commit()
        
        logger.info(f"WebSocket disconnected for user {user_id}")
        
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        
        # Clean up on error
        manager.disconnect(websocket, user_id)
        
        # Log the error
        log_audit_event(
            db,
            action="websocket_error",
            user_id=user_id,
            ip_address=websocket.client.host if websocket.client else None,
            metadata_json={"error": str(e)}
        )
        db.commit()


@router.websocket("/agent-log")
async def agent_log_websocket(
    websocket: WebSocket,
    db: Session = Depends(get_db),
):
    """Admin-only WebSocket endpoint for live agent log events."""
    token = _extract_websocket_token(websocket)
    if not token:
        await websocket.close(code=4401, reason="Missing authentication token")
        return
    try:
        claims = decode_token(token)
        if claims.get("token_type") != "access":
            await websocket.close(code=4403, reason="Forbidden")
            return
        user_id = int(claims.get("sub"))
    except (ValueError, TypeError):
        await websocket.close(code=4401, reason="Invalid token")
        return

    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role != "admin":
        await websocket.close(code=4403, reason="Admin role required")
        return

    await manager.connect_agent_log(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JSON format"}))
                continue

            if message.get("type") == "ping":
                await websocket.send_text(
                    json.dumps({"type": "pong", "timestamp": manager._get_timestamp()})
                )
            else:
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "subscription_acknowledged",
                            "data": {"channels": ["agent_log"], "message": "Subscribed to agent log"},
                            "timestamp": manager._get_timestamp(),
                        }
                    )
                )
    except WebSocketDisconnect:
        manager.disconnect_agent_log(websocket)
    except Exception as e:
        logger.error(f"Agent log WebSocket error: {e}")
        manager.disconnect_agent_log(websocket)


async def handle_subscription(websocket: WebSocket, user_id: int, channels: list):
    """
    Handle client subscription to specific notification channels.
    This could be extended to support fine-grained subscriptions.
    """
    # For now, we'll just acknowledge the subscription
    # In a full implementation, you might track user subscriptions per channel
    
    valid_channels = ["scan_events", "security_alerts", "system_alerts", "all"]
    subscribed_channels = [ch for ch in channels if ch in valid_channels]
    
    await websocket.send_text(json.dumps({
        "type": "subscription_acknowledged",
        "data": {
            "channels": subscribed_channels,
            "message": f"Subscribed to {', '.join(subscribed_channels)}"
        },
        "timestamp": manager._get_timestamp()
    }))
    
    logger.info(f"User {user_id} subscribed to channels: {subscribed_channels}")


@router.get("/ws/status")
async def websocket_status(current_user: User = Depends(get_current_user)):
    """
    Get WebSocket connection status for the current user.
    """
    user_connections = manager.active_connections.get(current_user.id, set())
    
    return {
        "user_id": current_user.id,
        "connected": len(user_connections) > 0,
        "connection_count": len(user_connections),
        "timestamp": manager._get_timestamp()
    }


@router.post("/ws/notify")
async def send_notification(
    message: Dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Send a test notification to the current user's WebSocket connections.
    This is primarily for testing purposes.
    """
    from app.services.websocket import notify_user_notification
    
    await notify_user_notification(
        current_user.id,
        message.get("title", "Test Notification"),
        message.get("message", "This is a test notification"),
        message.get("type", "info")
    )
    
    # Log the test notification
    log_audit_event(
        db,
        action="test_notification_sent",
        user_id=current_user.id,
        ip_address="127.0.0.1",  # This would come from request in real implementation
        metadata_json={"message": message}
    )
    
    return {
        "success": True,
        "message": "Test notification sent",
        "timestamp": manager._get_timestamp()
    }
