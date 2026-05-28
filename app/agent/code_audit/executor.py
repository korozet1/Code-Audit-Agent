from __future__ import annotations

from pathlib import Path
from typing import Any

from .merge import merge_scan_results
from .reporter import generate_report
from .scanner import (
    codeql_result_path,
    fortify_result_path,
    read_json,
    scan_with_codeql,
    scan_with_fortify,
    write_json,
)
from .state import CodeAuditState


def next_task(state: CodeAuditState) -> str | None:
    plan = state.get("plan") or []
    return plan[0] if plan else None


def pop_plan(state: CodeAuditState) -> list[str]:
    plan = state.get("plan") or []
    return plan[1:] if plan else []


async def executor(state: CodeAuditState) -> dict[str, Any]:
    """执行当前计划步骤。

    Args:
        state: 当前 LangGraph 状态。

    Returns:
        状态增量。即使某一步失败，也会记录错误并推进到下一步。
    """
    task = next_task(state)
    if not task:
        return {}

    request = state["request"]
    project_dir = Path(request["project_path"]).resolve()

    try:
        if "[codeql_scan]" in task:
            result = await scan_with_codeql(request)
            return {
                "plan": pop_plan(state),
                "codeql_result": result,
                "past_steps": [(task, {"status": "success", "result_path": str(codeql_result_path(project_dir))})],
            }

        if "[fortify_scan]" in task:
            result = await scan_with_fortify(request)
            return {
                "plan": pop_plan(state),
                "fortify_result": result,
                "past_steps": [(task, {"status": "success", "result_path": str(fortify_result_path(project_dir))})],
            }

        if "[merge_results]" in task:
            codeql_result = state.get("codeql_result") or read_json(codeql_result_path(project_dir))
            fortify_result = state.get("fortify_result") or read_json(fortify_result_path(project_dir))
            if not codeql_result and not fortify_result:
                raise RuntimeError("No CodeQL or Fortify result JSON is available for merge.")

            merged = merge_scan_results(str(project_dir), codeql_result, fortify_result)
            merged_path = Path(request.get("merged_output") or project_dir / "reports" / "merged-analysis.json")
            if not merged_path.is_absolute():
                merged_path = project_dir / merged_path
            merged_path = merged_path.resolve()
            write_json(merged, merged_path)
            return {
                "plan": pop_plan(state),
                "merged_result": merged,
                "merged_path": str(merged_path),
                "past_steps": [(task, {"status": "success", "merged_path": str(merged_path)})],
            }

        if "[generate_report]" in task:
            codeql_result = state.get("codeql_result") or read_json(codeql_result_path(project_dir))
            fortify_result = state.get("fortify_result") or read_json(fortify_result_path(project_dir))
            if not codeql_result and not fortify_result:
                raise RuntimeError("No CodeQL or Fortify result JSON is available for report generation.")

            merged_result = state.get("merged_result")
            if not merged_result:
                merged_result = merge_scan_results(str(project_dir), codeql_result, fortify_result)

            report, report_path, llm_error = await generate_report(
                request,
                codeql_result,
                fortify_result,
                merged_result,
            )
            errors = [f"LLM report fallback used: {llm_error}"] if llm_error else []
            return {
                "plan": pop_plan(state),
                "report": report,
                "report_path": report_path,
                "response": report,
                "errors": errors,
                "past_steps": [(task, {"status": "success", "report_path": report_path})],
            }

        return {
            "plan": pop_plan(state),
            "errors": [f"Unknown task skipped: {task}"],
            "past_steps": [(task, {"status": "skipped"})],
        }

    except Exception as exc:
        return {
            "plan": pop_plan(state),
            "errors": [f"{task}: {exc}"],
            "past_steps": [(task, {"status": "failed", "error": str(exc)})],
        }


__all__ = ["executor"]
