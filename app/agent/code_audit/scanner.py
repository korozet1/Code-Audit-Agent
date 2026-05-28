from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.config import config
from ccamp.shared.mcp_client import call_mcp_tool
from ccamp.shared.report_schema import normalize_scan_result


def reports_dir(project_dir: Path) -> Path:
    return project_dir / "reports"


def write_json(payload: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )


def read_json(output_path: Path) -> dict[str, Any] | None:
    if not output_path.exists():
        return None
    return json.loads(output_path.read_text(encoding="utf-8-sig"))


def detect_codeql_language(project_dir: Path, requested_language: str) -> str:
    if requested_language and requested_language != "auto":
        return requested_language
    if any(project_dir.rglob("*.java")) or (project_dir / "pom.xml").exists():
        return "java"
    if any(project_dir.rglob("*.py")):
        return "python"
    if any(project_dir.rglob("*.go")):
        return "go"
    if any(project_dir.rglob("*.js")) or any(project_dir.rglob("*.ts")):
        return "javascript"
    return "java"


def codeql_result_path(project_dir: Path) -> Path:
    return reports_dir(project_dir) / "codeql-mcp-result.json"


def fortify_result_path(project_dir: Path) -> Path:
    return reports_dir(project_dir) / "fortify-mcp-result.json"


async def scan_with_codeql(request: dict[str, Any]) -> dict[str, Any]:
    """调用 CodeQL MCP 并写入标准化结果 JSON。

    Args:
        request: CodeAuditRequest.model_dump() 得到的请求字典。

    Returns:
        标准化后的 CodeQL 扫描结果。
    """
    project_dir = Path(request["project_path"]).resolve()
    language = detect_codeql_language(project_dir, request.get("codeql_language", "auto"))
    arguments: dict[str, Any] = {
        "project_path": str(project_dir),
        "language": language,
        "source_root": request.get("codeql_source_root") or ".",
        "build_mode": request.get("codeql_build_mode") or "none",
        "timeout_seconds": request.get("codeql_timeout_seconds") or 3600,
    }

    optional_map = {
        "codeql_queries": "queries",
        "codeql_database_path": "database_path",
        "codeql_output_file": "output_file",
        "codeql_output_format": "output_format",
    }
    for request_name, tool_name in optional_map.items():
        value = request.get(request_name)
        if value:
            arguments[tool_name] = value

    max_results = int(request.get("max_codeql_results") or 0)
    if max_results > 0:
        arguments["max_results"] = max_results

    raw_result = await call_mcp_tool(
        config.codeql_mcp_url,
        "scan_project_with_codeql",
        arguments,
    )
    normalized = normalize_scan_result(raw_result)
    write_json(normalized, codeql_result_path(project_dir))
    return normalized


async def scan_with_fortify(request: dict[str, Any]) -> dict[str, Any]:
    """调用 Fortify MCP 并写入标准化结果 JSON。

    Args:
        request: CodeAuditRequest.model_dump() 得到的请求字典。

    Returns:
        标准化后的 Fortify 扫描结果。
    """
    project_dir = Path(request["project_path"]).resolve()
    arguments: dict[str, Any] = {
        "project_path": str(project_dir),
        "timeout_seconds": request.get("fortify_timeout_seconds") or 1800,
    }
    max_findings = int(request.get("max_fortify_findings") or 0)
    if max_findings > 0:
        arguments["max_findings"] = max_findings

    raw_result = await call_mcp_tool(
        config.fortify_mcp_url,
        "scan_project_with_fortify",
        arguments,
    )
    normalized = normalize_scan_result(raw_result)
    write_json(normalized, fortify_result_path(project_dir))
    return normalized


__all__ = [
    "codeql_result_path",
    "detect_codeql_language",
    "fortify_result_path",
    "read_json",
    "reports_dir",
    "scan_with_codeql",
    "scan_with_fortify",
    "write_json",
]
