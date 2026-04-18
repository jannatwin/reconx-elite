import json
import logging
from datetime import datetime
from typing import Any

from fastapi import WebSocket
from fastapi.websockets import WebSocketDisconnect

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self) -> None:
        self.connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str) -> None:
        await websocket.accept()
        self.connections.setdefault(session_id, []).append(websocket)
        logger.info("WebSocket connected for session %s", session_id)

    async def disconnect(self, websocket: WebSocket, session_id: str) -> None:
        if session_id not in self.connections:
            return
        try:
            self.connections[session_id].remove(websocket)
        except ValueError:
            pass
        if not self.connections[session_id]:
            del self.connections[session_id]
        logger.info("WebSocket disconnected for session %s", session_id)

    async def _safe_send(self, websocket: WebSocket, message: str) -> None:
        try:
            await websocket.send_text(message)
        except (WebSocketDisconnect, RuntimeError, ConnectionResetError):
            logger.debug("WebSocket client disconnected during send")

    async def broadcast(self, session_id: str, message_type: str, data: Any) -> None:
        message = json.dumps(
            {
                "type": message_type,
                "data": data,
                "session_id": session_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        )
        if session_id not in self.connections:
            return
        for websocket in list(self.connections.get(session_id, [])):
            await self._safe_send(websocket, message)

    async def send_log(
        self,
        session_id: str,
        level: str,
        message: str,
        model_role: str | None = None,
        phase: str | None = None,
    ) -> None:
        await self.broadcast(
            session_id,
            "log",
            {
                "level": level,
                "message": message,
                "model_role": model_role,
                "phase": phase,
            },
        )

    async def send_finding(self, session_id: str, finding_dict: dict) -> None:
        await self.broadcast(session_id, "finding", finding_dict)

    async def send_phase_update(self, session_id: str, phase: str, status: str) -> None:
        await self.broadcast(
            session_id, "phase_update", {"phase": phase, "status": status}
        )

    async def send_stats(self, session_id: str, stats_dict: dict) -> None:
        await self.broadcast(session_id, "stats_update", stats_dict)

    async def send_complete(self, session_id: str, summary_dict: dict) -> None:
        await self.broadcast(session_id, "scan_complete", summary_dict)
