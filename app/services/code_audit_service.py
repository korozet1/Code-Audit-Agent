from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from app.agent.code_audit import build_code_audit_graph
from app.models.code_audit import CodeAuditEvent, CodeAuditRequest


class CodeAuditService:
    def __init__(self) -> None:
        self.graph = build_code_audit_graph()

    async def execute(self, request: CodeAuditRequest) -> AsyncGenerator[dict[str, Any], None]:
        """执行 CodeQL + Fortify 合并审计工作流。"""
        initial_state = {
            "request": request.model_dump(),
            "plan": [],
            "past_steps": [],
            "errors": [],
        }
        graph_config = {"configurable": {"thread_id": request.session_id}}

        yield CodeAuditEvent(
            type="start",
            stage="service",
            message="Code audit workflow started.",
            data={"session_id": request.session_id, "project_path": request.project_path},
        ).model_dump()

        last_report_path: str | None = None
        last_merged_path: str | None = None
        final_errors: list[str] = []

        async for event in self.graph.astream(initial_state, config=graph_config):
            for node_name, payload in event.items():
                if not isinstance(payload, dict):
                    continue

                if payload.get("report_path"):
                    last_report_path = payload["report_path"]
                if payload.get("merged_path"):
                    last_merged_path = payload["merged_path"]
                if payload.get("errors"):
                    final_errors.extend(payload["errors"])

                yield self._format_node_event(node_name, payload)

        yield CodeAuditEvent(
            type="complete" if not final_errors else "complete_with_errors",
            stage="service",
            message="Code audit workflow completed.",
            data={
                "session_id": request.session_id,
                "report_path": last_report_path,
                "merged_path": last_merged_path,
                "errors": final_errors,
            },
        ).model_dump()

    def _format_node_event(self, node_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if node_name == "planner":
            return CodeAuditEvent(
                type="plan",
                stage=node_name,
                message="Plan generated.",
                data={"plan": payload.get("plan", [])},
            ).model_dump()

        if node_name == "executor":
            step = (payload.get("past_steps") or [("", {})])[-1]
            return CodeAuditEvent(
                type="step_complete",
                stage=node_name,
                message=str(step[0]),
                data={
                    "step_result": step[1],
                    "errors": payload.get("errors", []),
                    "report_path": payload.get("report_path"),
                    "merged_path": payload.get("merged_path"),
                },
            ).model_dump()

        if node_name == "replanner":
            return CodeAuditEvent(
                type="replan",
                stage=node_name,
                message="Workflow decision updated.",
                data={"response": payload.get("response")},
            ).model_dump()

        return CodeAuditEvent(
            type="event",
            stage=node_name,
            message="Workflow event.",
            data=payload,
        ).model_dump()


code_audit_service = CodeAuditService()


__all__ = ["CodeAuditService", "code_audit_service"]
