from __future__ import annotations

from typing import Any

from .state import CodeAuditState


async def replanner(state: CodeAuditState) -> dict[str, Any]:
    """决定继续执行还是结束。

    Args:
        state: 当前 LangGraph 状态。

    Returns:
        需要补充的状态增量。
    """
    if state.get("plan"):
        return {}

    if state.get("response"):
        return {}

    errors = state.get("errors") or []
    if errors:
        return {"response": "Code audit finished with errors: " + "; ".join(errors)}
    return {"response": "Code audit finished."}


def should_continue(state: CodeAuditState) -> str:
    return "continue" if state.get("plan") else "respond"


__all__ = ["replanner", "should_continue"]
