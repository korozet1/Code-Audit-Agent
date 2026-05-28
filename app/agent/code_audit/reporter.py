from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from textwrap import dedent
from typing import Any

from app.core.llm import chat_completion


REPORT_OUTLINE = """
Fortify + CodeQL 扫描结果合并分析报告
1. 扫描概览
2. 合并规则与风险口径
3. 漏洞类型分布
4. 两工具重合与差异
5. 去重分析
6. 疑似误报与需人工确认项
7. P0/P1 优先复核清单
8. 按漏洞类型的修复建议
9. 给 AI Agent 的落地处理建议
附录 A：合并明细清单
""".strip()


def report_output_path(project_dir: Path, configured_path: str | None) -> Path:
    if configured_path:
        path = Path(configured_path).expanduser()
        if not path.is_absolute():
            path = project_dir / path
        return path.resolve()
    return (project_dir / "reports" / "fortify-codeql-merged-report.md").resolve()


def md_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        text = ", ".join(str(item) for item in value)
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    return text.replace("\n", "<br>").replace("|", "\\|")


def table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    if not rows:
        lines.append("| " + " | ".join("无" if index == 0 else "" for index in range(len(headers))) + " |")
        return lines
    for row in rows:
        lines.append("| " + " | ".join(md_cell(item) for item in row) + " |")
    return lines


def lines_text(lines: list[int]) -> str:
    return ", ".join(str(line) for line in lines)


def basename(path: Any) -> str:
    if not path:
        return ""
    return Path(str(path)).name


def field_line(label: str, value: Any) -> str:
    return f"- **{label}**：{md_cell(value)}"


def render_issue_cards(
    prefix: str,
    items: list[dict[str, Any]],
    fields: list[tuple[str, str]],
) -> list[str]:
    if not items:
        return ["无。"]

    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        title_parts = [
            str(item.get("priority") or "").strip(),
            str(item.get("vulnerability_type") or "").strip(),
            basename(item.get("file")),
        ]
        title = " | ".join(part for part in title_parts if part)
        lines.extend([
            f"#### {prefix}-{index:03d} {title}",
            "",
        ])
        for label, key in fields:
            value: Any
            if key == "lines":
                value = lines_text(item.get("lines") or [])
            else:
                value = item.get(key)
            if value not in (None, "", []):
                lines.append(field_line(label, value))
        lines.append("")
    return lines


def tool_summary_rows(merged_result: dict[str, Any]) -> list[list[Any]]:
    rows = []
    for name in ["fortify", "codeql"]:
        item = (merged_result.get("tool_summaries") or {}).get(name, {})
        rows.append([
            name,
            item.get("status"),
            item.get("total_findings"),
            item.get("returned_findings"),
            item.get("severity_count"),
            item.get("raw_report_path"),
        ])
    return rows


def source_snippet(project_dir: Path, relative_file: str, lines: list[int], context: int = 5) -> str:
    if not relative_file or relative_file == "<unknown>" or not lines:
        return ""
    path = Path(relative_file)
    if not path.is_absolute():
        path = project_dir / path
    if not path.exists() or not path.is_file():
        return ""

    text_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = []
    for line in lines[:5]:
        start = max(line - context, 1)
        end = min(line + context, len(text_lines))
        block = []
        for number in range(start, end + 1):
            prefix = ">>" if number == line else "  "
            block.append(f"{prefix} {number}: {text_lines[number - 1]}")
        selected.append("\n".join(block))
    return "\n---\n".join(selected)


def review_payload(
    project_dir: Path,
    merged_result: dict[str, Any],
    max_candidates: int = 80,
) -> str:
    false_positive_candidates = []
    for item in (merged_result.get("false_positive_review_candidates") or [])[:max_candidates]:
        enriched = dict(item)
        enriched["source_snippet"] = source_snippet(
            project_dir,
            str(item.get("file") or ""),
            [line for line in item.get("lines", []) if isinstance(line, int)],
        )
        false_positive_candidates.append(enriched)

    payload = {
        "report_outline": REPORT_OUTLINE,
        "summary": merged_result.get("summary"),
        "direct_overlap_groups": merged_result.get("direct_overlap_groups"),
        "deduplication_candidates": (merged_result.get("deduplication_candidates") or [])[:max_candidates],
        "false_positive_review_candidates": false_positive_candidates,
        "important_rule": (
            "统计和完整明细由程序确定性生成。你只输出二次审计意见，不要重写统计表，"
            "不要新增 JSON 中不存在的文件、行号、规则或数量。"
        ),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


async def generate_expert_review(
    project_dir: Path,
    merged_result: dict[str, Any],
) -> tuple[str, str | None]:
    system_prompt = dedent(
        """
        你是资深代码审计工程师。你只负责对程序已经合并好的 Fortify + CodeQL 结果做二次审计意见。
        输出 Markdown，必须包含三个小节：
        ### 去重复核意见
        ### 疑似误报/需确认复核意见
        ### 修复优先级调整建议

        约束：
        - 不要重写完整报告，不要生成扫描概览、类型分布和附录。
        - 不要编造 JSON 中不存在的文件、行号、规则或数量。
        - 去重判断要说明“合并处理”或“保留独立问题”的理由。
        - 误报判断只能使用“疑似误报”“需人工确认”“暂不建议判误报”，除非源码片段能明确证明，否则不要写“确定误报”。
        - 如果 source_snippet 为空，要明确说明证据不足，需要人工看源码。
        """
    ).strip()
    user_prompt = "请对以下合并结果做二次审计复核：\n\n" + review_payload(project_dir, merged_result)
    try:
        review = await chat_completion(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=5000,
        )
        return review.strip(), None
    except Exception as exc:
        return f"> 大模型二次审计意见生成失败：{exc}", str(exc)


def render_deterministic_report(
    merged_result: dict[str, Any],
    expert_review: str,
) -> str:
    summary = merged_result.get("summary") or {}
    type_distribution = merged_result.get("type_distribution") or []
    direct_overlap_groups = merged_result.get("direct_overlap_groups") or []
    high_priority_groups = merged_result.get("high_priority_groups") or []
    deduplication_candidates = merged_result.get("deduplication_candidates") or []
    false_positive_candidates = merged_result.get("false_positive_review_candidates") or []
    groups = merged_result.get("groups") or []

    lines = [
        "# Fortify + CodeQL 扫描结果合并分析报告",
        "",
        f"报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"项目路径：`{merged_result.get('project_path')}`",
        "",
        (
            f"结论一句话：两个工具原始共 {summary.get('raw_total_findings')} 条结果，"
            f"合并为 {summary.get('merged_groups')} 个待审核问题组；"
            f"其中 P0/P1 共 {summary.get('high_priority_groups')} 组，"
            f"去重候选 {summary.get('deduplication_candidates')} 组，"
            f"疑似误报/需确认候选 {summary.get('false_positive_review_candidates')} 组。"
        ),
        "",
        "## 1. 扫描概览",
        "",
        *table(
            ["工具", "状态", "总数", "返回数", "严重级别", "原始报告"],
            tool_summary_rows(merged_result),
        ),
        "",
        "## 2. 合并规则与风险口径",
        "",
        "- 合并键：漏洞类型归一化 + 文件路径。",
        "- 直接重合：同一漏洞类型且同一文件被两个工具同时发现。",
        "- 类型重合：同一漏洞类型被两个工具发现，但不一定落在同一文件。",
        "- P0：双工具确认或高危可利用类型；P1：其他高风险；P2：中风险；P3：低风险/质量建议。",
        "- 误报判断：没有源码证据时只能标记为疑似误报或需人工确认。",
        "",
        "## 3. 漏洞类型分布",
        "",
        *table(
            ["漏洞类型", "Fortify", "CodeQL", "原始条数", "来源"],
            [
                [
                    item.get("vulnerability_type"),
                    item.get("fortify"),
                    item.get("codeql"),
                    item.get("raw_count"),
                    item.get("sources"),
                ]
                for item in type_distribution
            ],
        ),
        "",
        "## 4. 两工具重合与差异",
        "",
        "### 4.1 直接重合问题组",
        "",
        *render_issue_cards(
            "O",
            direct_overlap_groups,
            [
                ("文件", "file"),
                ("来源", "sources"),
                ("严重级别", "severities"),
                ("行号", "lines"),
                ("规则", "rules"),
                ("原始条数", "finding_count"),
            ],
        ),
        "",
        "### 4.2 工具侧差异",
        "",
        *table(
            ["漏洞类型", "Fortify", "CodeQL", "差异说明"],
            [
                [
                    item.get("vulnerability_type"),
                    item.get("fortify"),
                    item.get("codeql"),
                    "仅 Fortify" if item.get("fortify") and not item.get("codeql")
                    else "仅 CodeQL" if item.get("codeql") and not item.get("fortify")
                    else "双工具覆盖",
                ]
                for item in type_distribution
            ],
        ),
        "",
        "## 5. 去重分析",
        "",
        "以下条目由程序完整列出所有去重候选，大模型复核意见见后续小节。",
        "",
        *render_issue_cards(
            "D",
            deduplication_candidates,
            [
                ("文件", "file"),
                ("来源", "sources"),
                ("原始条数", "finding_count"),
                ("行号", "lines"),
                ("规则", "rules"),
                ("程序建议", "dedup_suggestion"),
                ("理由", "reason"),
            ],
        ),
        "",
        "## 6. 疑似误报与需人工确认项",
        "",
        "以下条目由程序完整列出所有需复核候选，大模型复核意见见后续小节。",
        "",
        *render_issue_cards(
            "F",
            false_positive_candidates,
            [
                ("文件", "file"),
                ("来源", "sources"),
                ("行号", "lines"),
                ("规则", "rules"),
                ("程序建议", "review_suggestion"),
                ("理由", "reason"),
            ],
        ),
        "",
        "### 6.1 大模型二次审计意见",
        "",
        expert_review,
        "",
        "## 7. P0/P1 优先复核清单",
        "",
        *render_issue_cards(
            "P",
            high_priority_groups,
            [
                ("文件", "file"),
                ("来源", "sources"),
                ("严重级别", "severities"),
                ("行号", "lines"),
                ("规则", "rules"),
                ("原始条数", "finding_count"),
            ],
        ),
        "",
        "## 8. 按漏洞类型的修复建议",
        "",
        "- SQL 注入：统一使用参数化查询，禁止字符串拼接 SQL；补充 DAO 层安全单元测试。",
        "- XXE/XML 实体注入：禁用 DTD、外部实体和外部参数实体；集中封装 XML parser 工厂。",
        "- SSRF：建立统一 URL 校验组件，限制协议、域名/IP 白名单，阻断内网和云元数据地址。",
        "- XSS：按输出上下文做 HTML/JavaScript/URL 编码，避免直接写入 `HttpServletResponse`。",
        "- 命令执行：避免拼接命令；无法避免时使用参数数组、白名单和最小权限运行。",
        "- 反序列化：禁止反序列化不可信数据，升级高风险组件，加入类型白名单。",
        "- 路径遍历/文件上传：标准化路径并校验仍位于安全根目录，文件名使用安全重命名策略。",
        "- 日志注入：日志写入前移除 CR/LF 和控制字符，避免把未净化输入写入结构化日志字段。",
        "",
        "## 9. 给 AI Agent 的落地处理建议",
        "",
        "- 先读取 `merged-analysis.json`，以 `groups` 为工单粒度，而不是以原始 finding 为工单粒度。",
        "- 对 `deduplication_candidates` 生成合并工单，对 `false_positive_review_candidates` 生成复核工单。",
        "- P0/P1 问题优先生成补丁；P2/P3 问题可批量处理或进入安全债队列。",
        "- 修复后重新运行 CodeQL 和 Fortify，并对比本报告中的文件、规则和行号是否消除。",
        "- 人工确认的误报应写入 suppression 或规则降级配置，形成反馈闭环。",
        "",
        "## 附录 A：合并明细清单",
        "",
        "以下完整列出所有合并问题组，避免模型摘要导致明细丢失。",
        "",
        *render_issue_cards(
            "A",
            groups,
            [
                ("文件", "file"),
                ("来源", "sources"),
                ("严重级别", "severities"),
                ("行号", "lines"),
                ("规则", "rules"),
                ("原始条数", "finding_count"),
                ("消息摘要", "messages"),
            ],
        ),
    ]
    return "\n".join(lines)


async def generate_report(
    request: dict[str, Any],
    codeql_result: dict[str, Any] | None,
    fortify_result: dict[str, Any] | None,
    merged_result: dict[str, Any],
) -> tuple[str, str, str | None]:
    """生成确定性 Markdown 报告，并嵌入大模型二次审计意见。"""
    project_dir = Path(request["project_path"]).resolve()
    output_path = report_output_path(project_dir, request.get("report_output"))
    expert_review, error_message = await generate_expert_review(project_dir, merged_result)
    report = render_deterministic_report(merged_result, expert_review)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8-sig")
    return report, str(output_path), error_message


__all__ = ["REPORT_OUTLINE", "generate_report", "render_deterministic_report"]
