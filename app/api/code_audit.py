from __future__ import annotations

import json

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from app.models.code_audit import CodeAuditRequest
from app.services.code_audit_service import code_audit_service


router = APIRouter(prefix="/code-audit", tags=["code-audit"])


@router.post("/stream")
async def run_code_audit_stream(request: CodeAuditRequest):
    async def event_generator():
        async for event in code_audit_service.execute(request):
            yield {
                "event": "message",
                "data": json.dumps(event, ensure_ascii=False),
            }
            if event.get("type") in {"complete", "complete_with_errors", "error"}:
                break

    return EventSourceResponse(event_generator())


__all__ = ["router"]
