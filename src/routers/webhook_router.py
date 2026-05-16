from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from typing import List, Dict
import json
from src.database import get_session
from src.model import AuditEvent
from src.loggings import logging

webhook_router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])

# Simple WebSocket Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, project_id: str):
        await websocket.accept()
        if project_id not in self.active_connections:
            self.active_connections[project_id] = []
        self.active_connections[project_id].append(websocket)

    def disconnect(self, websocket: WebSocket, project_id: str):
        if project_id in self.active_connections:
            self.active_connections[project_id].remove(websocket)

    async def broadcast_to_project(self, project_id: str, message: dict):
        if project_id in self.active_connections:
            for connection in self.active_connections[project_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass

manager = ConnectionManager()

@webhook_router.post(
    "/audit",
    status_code=status.HTTP_200_OK,
    summary="Receive audit logs from Lobster Trap",
    description="Updates existing request logs with security verdicts from Lobster Trap and broadcasts them via WebSockets.",
)
async def receive_audit_log(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """
    Correlates security verdicts with existing observability logs.
    """
    try:
        try:
            payload = await request.json()
        except json.JSONDecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload.")

        # Correlation logic
        request_id = payload.get("request_id")
        project_id = payload.get("project_id")
        verdict = payload.get("verdict")
        metadata = payload.get("metadata", {})
        
        if not request_id:
            logging.warning("Received webhook without request_id")
            return {"status": "ignored", "reason": "missing request_id"}
        
        # Find existing log created by the Gateway
        query = select(AuditEvent).where(AuditEvent.request_id == request_id)
        result = await session.execute(query)
        audit_event = result.scalar_one_or_none()
        
        if audit_event:
            # Update existing entry with security data
            audit_event.verdict = verdict
            audit_event.metadata_ = metadata
            session.add(audit_event)
        else:
            # If for some reason the gateway didn't create it (e.g. timeout), create it now
            audit_event = AuditEvent(
                project_id=project_id,
                request_id=request_id,
                verdict=verdict,
                metadata_=metadata
            )
            session.add(audit_event)
        
        await session.commit()
        await session.refresh(audit_event)
        
        # Broadcast to WebSocket
        await manager.broadcast_to_project(
            str(project_id),
            {
                "type": "AUDIT_EVENT",
                "data": {
                    "request_id": request_id,
                    "prompt_snippet": audit_event.prompt_snippet,
                    "verdict": verdict,
                    "model": audit_event.model_used,
                    "total_tokens": audit_event.total_tokens,
                    "metadata": metadata
                }
            }
        )
        
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error processing audit webhook: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process audit event.")

@webhook_router.websocket("/ws/audit/{project_id}")
async def websocket_audit_stream(websocket: WebSocket, project_id: str):
    await manager.connect(websocket, project_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, project_id)
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}")
        manager.disconnect(websocket, project_id)
