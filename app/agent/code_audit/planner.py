from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .state import CodeAuditState


class Plan(BaseModel):
    """审计计划的结构化输出。"""

    steps: list[str] = Field(
        default_factory=list,
        description="完成 CodeQL + Fortify 合并分析所需的执行步骤。",
    )


async def planner(state: CodeAuditState) -> dict[str, Any]:
    """生成固定的审计执行计划。

    Args:
        state: 当前 LangGraph 状态。

    Returns:
        包含 plan 的状态增量。
    """
    plan = Plan(
        steps=[
            "[codeql_scan] 调用 CodeQL MCP 完成扫描并保存 codeql-mcp-result.json",
            "[fortify_scan] 调用 Fortify MCP 完成扫描并保存 fortify-mcp-result.json",
            "[merge_results] 合并两个 MCP 结果并生成 merged-analysis.json",
            "[generate_report] 将两个 MCP 结果和合并分析交给大模型生成报告",
        ]
    )
    return {
        "plan": plan.steps,
        "past_steps": [("planner", {"steps": plan.steps})],
    }


__all__ = ["Plan", "planner"]
