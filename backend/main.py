import asyncio
import os
import uuid
from datetime import datetime, timezone
from typing import Any, TypedDict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from pydantic import BaseModel

from backend.ai_router import AIRouter
from backend.database import (
    Scan,
    Finding,
    AgentLog,
    create_all_tables,
    get_db,
    async_session,
)
from backend.orchestrator_7phase import SevenPhaseOrchestrator
from backend.tool_runner import ToolRunner
from backend.websocket_manager import WebSocketManager

load_dotenv()


# Pydantic models for API
class ScanRequest(BaseModel):
    target: str
    session_a_token: str | None = None
    session_b_token: str | None = None


class ScanResponse(BaseModel):
    session_id: str
    target: str
    status: str


app = FastAPI(title="ReconX-Elite - 7-Phase Autonomous Vulnerability Research Pipeline")
# Configure CORS origins from environment
cors_origins = (
    os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
)
if not cors_origins and os.getenv("ENVIRONMENT") != "production":
    # Fallback for development
    cors_origins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

ws_manager = WebSocketManager()
ai_router = AIRouter()
tool_runner = ToolRunner()

# Track background tasks to prevent orphaning
background_tasks = set()


@app.on_event("startup")
async def startup_event() -> None:
    max_retries = 3
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        try:
            await create_all_tables()
            break
        except Exception as e:
            if attempt == max_retries - 1:
                # Last attempt failed, log and continue with degraded functionality
                print(
                    f"Failed to initialize database after {max_retries} attempts: {str(e)}"
                )
                print("Application will continue with limited functionality")
            else:
                print(f"Database connection attempt {attempt + 1} failed: {str(e)}")
                print(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest) -> ScanResponse:
    """Start a 7-phase autonomous vulnerability research scan."""
    session_id = str(uuid.uuid4())
    scan = Scan(
        session_id=session_id,
        target=request.target,
        status="initializing",
        total_subdomains=0,
        total_live_hosts=0,
        total_findings=0,
    )
    async with async_session() as session:
        session.add(scan)
        await session.commit()

    # Prepare session tokens if provided
    session_tokens = {}
    if request.session_a_token:
        session_tokens["session_a"] = request.session_a_token
    if request.session_b_token:
        session_tokens["session_b"] = request.session_b_token

    # Start orchestrator in background with task tracking
    task = asyncio.create_task(
        _orchestrate_7phase(session_id, request.target, session_tokens)
    )
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)

    return ScanResponse(session_id=session_id, target=request.target, status="started")


async def _orchestrate_7phase(
    session_id: str, target: str, session_tokens: dict[str, str]
) -> None:
    """Execute 7-phase pipeline."""
    try:
        orchestrator = SevenPhaseOrchestrator(
            session_id=session_id,
            target=target,
            ws_manager=ws_manager,
            ai_router=ai_router,
            tool_runner=tool_runner,
            session_tokens=session_tokens,
        )

        result = await orchestrator.execute()

        # Update scan record
        async with async_session() as session:
            stmt = select(Scan).where(Scan.session_id == session_id)
            db_scan = await session.execute(stmt)
            scan_record = db_scan.scalar_one_or_none()
            if scan_record:
                scan_record.status = result.get("status", "complete")
                scan_record.completed_at = datetime.now(timezone.utc)
                await session.commit()

    except Exception as e:
        await ws_manager.send_log(
            session_id, "error", f"Pipeline execution failed: {str(e)}", phase="error"
        )
        async with async_session() as session:
            stmt = select(Scan).where(Scan.session_id == session_id)
            db_scan = await session.execute(stmt)
            scan_record = db_scan.scalar_one_or_none()
            if scan_record:
                scan_record.status = "failed"
                scan_record.error_message = str(e)
                await session.commit()


class ScanStatusResponse(TypedDict):
    session_id: str
    target: str
    status: str
    total_findings: int


@app.get("/api/scan/{session_id}/status")
async def scan_status(session_id: str) -> ScanStatusResponse:
    async with async_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.session_id == session_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {
            "session_id": scan.session_id,
            "target": scan.target,
            "status": scan.status,
            "total_findings": scan.total_findings,
        }


class FindingResponse(TypedDict):
    id: int
    vuln_type: str
    severity: str
    endpoint: str


class ScanFindingsResponse(TypedDict):
    session_id: str
    findings: list[FindingResponse]


@app.get("/api/scan/{session_id}/findings")
async def scan_findings(session_id: str) -> ScanFindingsResponse:
    async with async_session() as session:
        result = await session.execute(
            select(Finding).where(Finding.session_id == session_id)
        )
        findings = [
            dict(
                id=row.id,
                vuln_type=row.vuln_type,
                severity=row.severity,
                endpoint=row.endpoint,
            )
            for row in result.scalars().all()
        ]
        return {"session_id": session_id, "findings": findings}


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str) -> None:
    try:
        await ws_manager.connect(websocket, session_id)
        while True:
            try:
                # Set a timeout for receiving messages
                message = await asyncio.wait_for(
                    websocket.receive_text(), timeout=300.0
                )  # 5 minute timeout
                # Process the message if needed, or just acknowledge it
                if message == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                await websocket.send_text("ping")
                # Wait for pong response
                try:
                    pong = await asyncio.wait_for(
                        websocket.receive_text(), timeout=10.0
                    )
                    if pong != "pong":
                        break  # Unexpected response, close connection
                except asyncio.TimeoutError:
                    break  # No pong response, close connection
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(websocket, session_id)


class HealthResponse(TypedDict):
    status: str
    version: str
    mode: str


@app.get("/health")
def health() -> HealthResponse:
    return {"status": "ok", "version": "1.0.0", "mode": "Tactical Scanning"}
