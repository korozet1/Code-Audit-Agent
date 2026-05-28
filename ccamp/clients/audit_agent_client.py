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
        print("\nOutputs:")
        print(f"- report_path: {data.get('report_path')}")
        print(f"- merged_path: {data.get('merged_path')}")
        if data.get("errors"):
            print("- errors:")
            for item in data["errors"]:
                print(f"  - {item}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the CodeQL + Fortify code audit agent."
    )
    parser.add_argument("project_path", help="Project directory to scan.")
    parser.add_argument("--language", default="auto", help="CodeQL language. Default: auto.")
    parser.add_argument("--queries", default=None, help="CodeQL query suite or qlpack path.")
    parser.add_argument("--database-path", default=None, help="CodeQL database path.")
    parser.add_argument("--codeql-output", default=None, help="CodeQL raw output file.")
    parser.add_argument("--codeql-output-format", default=None, help="CodeQL output format.")
    parser.add_argument("--source-root", default=".", help="CodeQL source root.")
    parser.add_argument("--build-mode", default="none", help="CodeQL build mode.")
    parser.add_argument("--codeql-timeout-seconds", type=int, default=3600)
    parser.add_argument("--fortify-timeout-seconds", type=int, default=1800)
    parser.add_argument("--max-codeql-results", type=int, default=0)
    parser.add_argument("--max-fortify-findings", type=int, default=0)
    parser.add_argument("--max-report-findings", type=int, default=240)
    parser.add_argument("--report-output", default=None, help="Markdown report output path.")
    parser.add_argument("--merged-output", default=None, help="Merged analysis JSON output path.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
