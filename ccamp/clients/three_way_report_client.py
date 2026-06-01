from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.agent.code_audit_three_way_report import (
    ThreeWayReportRequest,
    generate_three_way_report,
)


def print_progress(message: str) -> None:
    print(f"[progress] {message}", flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="生成以 Fortify 为主线的 Fortify + CodeQL + AI 直接审代码三方对比报告。"
    )
    parser.add_argument("project_path", help="待审计项目目录。")
    parser.add_argument(
        "--merged-input",
        default=None,
        help="merged-analysis.json 路径。默认：<project>/reports/merged-analysis.json。",
    )
    parser.add_argument(
        "--ai-review-input",
        default=None,
        help="AI 直接审代码 Markdown 路径。默认：<project>/ai-code-review-result.md。",
    )
    parser.add_argument(
        "--report-output",
        default=None,
        help="Markdown 报告输出路径。默认：<project>/reports/fortify-codeql-ai-final-report.md。",
    )
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="可选的最大输出 token 数。不填写则使用服务商默认值。",
    )
    parser.add_argument("--max-merged-chars", type=int, default=0)
    parser.add_argument("--max-ai-review-chars", type=int, default=0)
    return parser


async def run(args: argparse.Namespace) -> None:
    result = await generate_three_way_report(
        ThreeWayReportRequest(
            project_path=args.project_path,
            merged_input=args.merged_input,
            ai_review_input=args.ai_review_input,
            report_output=args.report_output,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            max_merged_chars=args.max_merged_chars,
            max_ai_review_chars=args.max_ai_review_chars,
            progress_callback=print_progress,
        )
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


def main() -> None:
    parser = build_parser()
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
