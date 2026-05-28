from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class CodeAuditState(TypedDict, total=False):
    request: dict[str, Any]
    plan: list[str]
    past_steps: Annotated[list[tuple[str, Any]], operator.add]
    errors: Annotated[list[str], operator.add]
    codeql_result: dict[str, Any]
    fortify_result: dict[str, Any]
    merged_result: dict[str, Any]
    report: str
    report_path: str
    merged_path: str
    response: str


__all__ = ["CodeAuditState"]
