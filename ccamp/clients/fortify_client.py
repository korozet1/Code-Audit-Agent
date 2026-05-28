from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastmcp import Client

from ccamp.shared.constants import LOCAL_NO_PROXY
from ccamp.shared.env import get_required_env, load_project_env
from ccamp.shared.mcp_client import unwrap_tool_result
from ccamp.shared.report_schema import normalize_scan_result


load_project_env()

MCP_URL = get_required_env("FORTIFY_MCP_URL")


async def run(
    project_path: str,
    mcp_url: str = MCP_URL,
    build_id: str | None = None,
    source_path: str | None = None,
    build_command: list[str] | None = None,
    timeout_seconds: int = 1800,
    max_findings: int = 0,
    output: str | None = None,
) -> None:
    os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
    os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

    project_dir = Path(project_path).resolve()
    async with Client(mcp_url) as client:
        tools = await client.list_tools()
        print("Available tools:")
        for tool in tools:
            print(f"- {tool.name}")

        arguments: dict[str, Any] = {
            "project_path": str(project_dir),
            "timeout_seconds": timeout_seconds,
        }
        if build_id:
            arguments["build_id"] = build_id
        if source_path:
            arguments["source_path"] = source_path
        if build_command:
            arguments["build_command"] = build_command
        if max_findings > 0:
            arguments["max_findings"] = max_findings

        result = await client.call_tool("scan_project_with_fortify", arguments)

    payload = normalize_scan_result(unwrap_tool_result(result))
    output_path = (
        Path(output).resolve()
        if output
        else project_dir / "reports" / "fortify-mcp-result.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"\nFortify MCP result written to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the Fortify MCP server.")
    parser.add_argument("project_path", help="Project directory to scan.")
    parser.add_argument("--mcp-url", default=MCP_URL, help="Streamable HTTP MCP URL.")
    parser.add_argument("--build-id", default=None)
    parser.add_argument(
        "--source-path",
        default=None,
        help="Source path to translate. Defaults to <project>\\src when it exists.",
    )
    parser.add_argument(
        "--build-command",
        nargs="+",
        default=None,
        help="Optional build command, for example: mvn -DskipTests clean package",
    )
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--max-findings",
        type=int,
        default=0,
        help="Maximum findings to return. Use 0 to return all parsed results.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Write the normalized MCP result JSON to this path. "
            "Defaults to <project>\\reports\\fortify-mcp-result.json."
        ),
    )
    args = parser.parse_args()

    asyncio.run(
        run(
            project_path=args.project_path,
            mcp_url=args.mcp_url,
            build_id=args.build_id,
            source_path=args.source_path,
            build_command=args.build_command,
            timeout_seconds=args.timeout_seconds,
            max_findings=args.max_findings,
            output=args.output,
        )
    )


if __name__ == "__main__":
    main()
