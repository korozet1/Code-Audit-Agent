from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class CodeAuditRequest(BaseModel):
    """CodeQL + Fortify 合并审计请求。"""

    project_path: str = Field(description="待扫描项目目录。")
    session_id: str = Field(
        default_factory=lambda: uuid4().hex,
        description="会话 ID，用于隔离 LangGraph checkpointer 状态。",
    )
    codeql_language: str = Field(
        default="auto",
        description="CodeQL 语言。auto 会根据项目文件推断，无法推断时使用 java。",
    )
    codeql_queries: str | None = Field(
        default=None,
        description="CodeQL queries 或 qls 文件路径。不传时使用 CodeQL MCP 服务端默认值。",
    )
    codeql_database_path: str | None = Field(
        default=None,
        description="CodeQL database 输出目录。不传时使用服务端默认值。",
    )
    codeql_output_file: str | None = Field(
        default=None,
        description="CodeQL 原始报告输出路径。不传时使用服务端默认值。",
    )
    codeql_output_format: str | None = Field(
        default=None,
        description="CodeQL 输出格式。不传时使用服务端默认值。",
    )
    codeql_source_root: str = Field(default=".", description="CodeQL source-root 参数。")
    codeql_build_mode: str = Field(default="none", description="CodeQL build-mode 参数。")
    codeql_timeout_seconds: int = Field(default=3600, ge=1)
    fortify_timeout_seconds: int = Field(default=1800, ge=1)
    max_codeql_results: int = Field(
        default=0,
        ge=0,
        description="CodeQL MCP 返回结果数量上限，0 表示不限制。",
    )
    max_fortify_findings: int = Field(
        default=0,
        ge=0,
        description="Fortify MCP 返回结果数量上限，0 表示不限制。",
    )
    max_report_findings: int = Field(
        default=240,
        ge=1,
        description="发送给大模型的每个工具 finding 上限，避免上下文过长。",
    )
    report_output: str | None = Field(
        default=None,
        description="Markdown 报告输出路径。不传时写入 <project>/reports/fortify-codeql-merged-report.md。",
    )
    merged_output: str | None = Field(
        default=None,
        description="合并分析 JSON 输出路径。不传时写入 <project>/reports/merged-analysis.json。",
    )

    @field_validator("project_path")
    @classmethod
    def validate_project_path(cls, value: str) -> str:
        path = Path(value).expanduser()
        if not path.exists():
            raise ValueError(f"Project path does not exist: {path}")
        if not path.is_dir():
            raise ValueError(f"Project path is not a directory: {path}")
        return str(path.resolve())


class CodeAuditEvent(BaseModel):
    """SSE/CLI 统一事件格式。"""

    type: str
    stage: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


__all__ = ["CodeAuditEvent", "CodeAuditRequest"]
