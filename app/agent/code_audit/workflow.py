from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from .executor import executor
from .planner import planner
from .replanner import replanner, should_continue
from .state import CodeAuditState


class LocalCodeAuditGraph:
    """LangGraph 不可用时的降级执行器，保持同一组节点语义。"""

    async def astream(
        self,
        initial_state: CodeAuditState,
        config: dict[str, Any] | None = None,
    ) -> AsyncGenerator[dict[str, dict[str, Any]], None]:
        state: CodeAuditState = dict(initial_state)

        planner_delta = await planner(state)
        state.update(planner_delta)
        yield {"planner": planner_delta}

        while True:
            executor_delta = await executor(state)
            self._merge_state(state, executor_delta)
            yield {"executor": executor_delta}

            replanner_delta = await replanner(state)
            self._merge_state(state, replanner_delta)
            yield {"replanner": replanner_delta}

            if should_continue(state) != "continue":
                break

    def _merge_state(self, state: CodeAuditState, delta: dict[str, Any]) -> None:
        for key, value in delta.items():
            if key in {"past_steps", "errors"}:
                state.setdefault(key, [])
                state[key].extend(value)
            else:
                state[key] = value


def build_code_audit_graph():
    try:
        from langgraph.checkpoint.memory import MemorySaver
        from langgraph.graph import END, StateGraph
    except ModuleNotFoundError:
        return LocalCodeAuditGraph()

    workflow = StateGraph(CodeAuditState)
    workflow.add_node("planner", planner)
    workflow.add_node("executor", executor)
    workflow.add_node("replanner", replanner)
    workflow.set_entry_point("planner")
    workflow.add_edge("planner", "executor")
    workflow.add_edge("executor", "replanner")
    workflow.add_conditional_edges(
        "replanner",
        should_continue,
        {
            "continue": "executor",
            "respond": END,
        },
    )
    return workflow.compile(checkpointer=MemorySaver())


__all__ = ["build_code_audit_graph"]
