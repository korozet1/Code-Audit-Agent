from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.models.code_audit import CodeAuditRequest
from app.services.code_audit_service import code_audit_service


async def run(args: argparse.Namespace) -> None:
    request = CodeAuditRequest(
        project_path=args.project_path,
        codeql_language=args.language,
        codeql_queries=args.queries,
        codeql_database_path=args.database_path,
        codeql_output_file=args.codeql_output,
        codeql_output_format=args.codeql_output_format,
        codeql_source_root=args.source_root,
        codeql_build_mode=args.build_mode,
        codeql_timeout_seconds=args.codeql_timeout_seconds,
        fortify_timeout_seconds=args.fortify_timeout_seconds,
        max_codeql_results=args.max_codeql_results,
        max_fortify_findings=args.max_fortify_findings,
        max_report_findings=args.max_report_findings,
        report_output=args.report_output,
        merged_output=args.merged_output,
    )

    final_event: dict | None = None
    async for event in code_audit_service.execute(request):
        final_event = event
        event_type = event.get("type")
        message = event.get("message")
        data = event.get("data") or {}

        if event_type == "plan":
            print("Plan:")
            for step in data.get("plan", []):
                print(f"- {step}")
            continue

        if event_type == "step_complete":
            print(f"[{event_type}] {message}")
            step_result = data.get("step_result") or {}
            if step_result:
                print(json.dumps(step_result, ensure_ascii=False, indent=2))
            if data.get("errors"):
                print(json.dumps({"errors": data["errors"]}, ensure_ascii=False, indent=2))
            continue

        print(f"[{event_type}] {message}")
        if data:
            print(json.dumps(data, ensure_ascii=False, indent=2))

    if final_event:
        data = final_event.get("data") or {}
        print("\n输出：")
        print(f"- report_path: {data.get('report_path')}")
        print(f"- merged_path: {data.get('merged_path')}")
        if data.get("errors"):
            print("- 错误：")
            for item in data["errors"]:
                print(f"  - {item}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="运行 CodeQL + Fortify 代码审计 Agent。"
    )
    parser.add_argument("project_path", help="待扫描项目目录。")
    parser.add_argument("--language", default="auto", help="CodeQL 语言。默认：auto。")
    parser.add_argument("--queries", default=None, help="CodeQL 查询套件或 qlpack 路径。")
    parser.add_argument("--database-path", default=None, help="CodeQL 数据库路径。")
    parser.add_argument("--codeql-output", default=None, help="CodeQL 原始输出文件。")
    parser.add_argument("--codeql-output-format", default=None, help="CodeQL 输出格式。")
    parser.add_argument("--source-root", default=".", help="CodeQL 源码根目录。")
    parser.add_argument("--build-mode", default="none", help="CodeQL 构建模式。")
    parser.add_argument("--codeql-timeout-seconds", type=int, default=3600)
    parser.add_argument("--fortify-timeout-seconds", type=int, default=1800)
    parser.add_argument("--max-codeql-results", type=int, default=0)
    parser.add_argument("--max-fortify-findings", type=int, default=0)
    parser.add_argument("--max-report-findings", type=int, default=240)
    parser.add_argument("--report-output", default=None, help="Markdown 报告输出路径。")
    parser.add_argument("--merged-output", default=None, help="合并分析 JSON 输出路径。")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
