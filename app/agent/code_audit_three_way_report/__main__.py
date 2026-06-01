from __future__ import annotations

import argparse
import asyncio
import json

from .generator import ThreeWayReportRequest, generate_three_way_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="根据 merged-analysis.json 和 AI 代码审查 Markdown 生成以 Fortify 为主线的三方对比报告。"
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
    parser.add_argument(
        "--max-merged-chars",
        type=int,
        default=0,
        help="可选的 merged JSON 字符数上限。0 表示完整输入。",
    )
    parser.add_argument(
        "--max-ai-review-chars",
        type=int,
        default=0,
        help="可选的 AI 审查 Markdown 字符数上限。0 表示完整输入。",
    )
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
        )
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


def main() -> None:
    parser = build_parser()
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
