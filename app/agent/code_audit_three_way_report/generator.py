from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from textwrap import dedent
from typing import Any, Callable

from app.core.llm import chat_completion_stream


@dataclass(frozen=True)
class ThreeWayReportRequest:
    project_path: str
    merged_input: str | None = None
    ai_review_input: str | None = None
    report_output: str | None = None
    temperature: float = 0.1
    max_tokens: int | None = None
    max_merged_chars: int = 0
    max_ai_review_chars: int = 0
    progress_callback: Callable[[str], None] | None = None


@dataclass(frozen=True)
class ThreeWayReportResult:
    report_path: str
    merged_path: str
    ai_review_path: str
    warning: str | None = None


def default_merged_path(project_dir: Path) -> Path:
    return (project_dir / "reports" / "merged-analysis.json").resolve()


def default_ai_review_path(project_dir: Path) -> Path:
    return (project_dir / "ai-code-review-result.md").resolve()


def default_report_path(project_dir: Path) -> Path:
    return (project_dir / "reports" / "fortify-codeql-ai-final-report.md").resolve()


def resolve_path(project_dir: Path, configured_path: str | None, default_path: Path) -> Path:
    if not configured_path:
        return default_path
    path = Path(configured_path).expanduser()
    if not path.is_absolute():
        path = project_dir / path
    return path.resolve()


def read_text_auto(path: Path) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def read_json_auto(path: Path) -> dict[str, Any]:
    text = read_text_auto(path)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} 必须包含 JSON 对象。")
    return data


def maybe_limit_text(text: str, max_chars: int, label: str) -> tuple[str, str | None]:
    if max_chars <= 0 or len(text) <= max_chars:
        return text, None
    limited = text[:max_chars]
    warning = f"{label} 已从 {len(text)} 个字符裁剪到 {max_chars} 个字符。"
    return limited, warning


def build_system_prompt() -> str:
    return dedent(
        """
        你是资深代码安全审计工程师，负责根据 Fortify、CodeQL 和 AI 直接审代码结果生成最终 Markdown 审计报告。

三路材料定义：
- Fortify 是主来源，决定最终问题全集。
- CodeQL 只作为 Fortify 问题的佐证，佐证数据来自 merged-analysis.json 中的 codeql_evidence。
- AI 直接审代码结果是第三路佐证，用于增强判断、误报复核和优先级调整。

        必须遵守的合并口径：
- 最终问题清单只能以 merged-analysis.json 中的 Fortify 主问题组为准。
- 不要把 CodeQL 独有问题或 AI 独有问题新增到最终问题清单。
- AI 结果只有在与 Fortify 主问题组按同文件、同漏洞类型、同代码位置或同安全语义匹配时，才能作为佐证。
- AI 独有观察项只能放在“非 Fortify 主线观察项”中，并明确说明默认不纳入最终漏洞清单。
- 不要编造输入材料中不存在的文件、行号、规则、数量、漏洞或证据。
- 误报判断只能使用“疑似误报”“需人工确认”“证据不足”等谨慎表述，除非输入材料明确证明，否则不要写“确定误报”。

        完整性要求：
- merged-analysis.json.summary.merged_groups 是最终 Fortify 主问题组数量，附录 A 必须逐个列出，不允许省略，不允许写“其余略”“同上”。
- merged-analysis.json.type_distribution 中的每一个 Fortify 漏洞类别都必须在“Fortify 主问题全集统计”和“按漏洞类型的修复建议”中出现。
- 每个 Fortify 主问题组至少要说明：文件、漏洞类型、优先级、Fortify 条数、CodeQL 佐证条数、AI 佐证结论、人工确认建议。

        Markdown 版式硬性要求：
        - 全文只能有一个一级标题，且只能出现在报告开头。
        - 主章节只能使用二级标题，例如“## 1. 扫描与输入概览”。
        - 单个漏洞条目、附录条目只能使用三级标题，例如“### A-001 P1-高风险 | SQL Injection | src/main/java/X.java”。
        - 禁止使用四级及更深标题，避免层级过碎。
        - 禁止使用“同上”“同前”“略”“其余类似”“参见前文”“same as above”等省略性表达。
        - 禁止输出超宽总表。总览表只放统计项，单个问题的详细证据放在该问题自己的小表格里。
        - 表格内容必须短：长路径、长规则、长解释不要全部塞入表格，应在表格后的“分析结论”和“处理建议”中展开。
        - 单个问题的 Fortify / CodeQL / AI 三方对比必须使用固定表格列：来源、命中状态、证据摘要、位置、结论。
        - 每个附录 A 条目都必须独立完整，不能依赖前文。
        - 直接输出最终报告正文，不要解释推理过程，不要输出分析笔记或计划过程。
        """
    ).strip()


def build_user_prompt(
    project_dir: Path,
    merged_path: Path,
    merged_text: str,
    ai_review_path: Path,
    ai_review_text: str,
    warnings: list[str],
) -> str:
    warning_text = "\n".join(f"- {item}" for item in warnings) if warnings else "- 无"
    return dedent(
        f"""
        请根据下面两个输入生成一份新的 Fortify + CodeQL + AI 三方对比审计报告。整份报告必须使用简体中文和 Markdown。

项目路径：
`{project_dir}`

输入文件：
- merged-analysis.json: `{merged_path}`
- ai-code-review-result.md: `{ai_review_path}`

输入裁剪说明：
{warning_text}

报告必须包含以下章节，并严格使用这些二级标题：
## 1. 扫描与输入概览
## 2. 三方合并规则与风险口径
## 3. Fortify 主问题全集统计
## 4. 三方重合与差异分析
## 5. 去重分析
## 6. 疑似误报与需人工确认项
## 7. P0/P1 优先复核清单
## 8. AI 直接审代码结果对 Fortify 主线的补充判断
## 9. 按漏洞类型的修复建议
## 10. 给 AI Agent 的落地处理建议
## 附录 A：Fortify 主问题组三方明细
## 附录 B：非 Fortify 主线观察项

输出要求：
- 全文只允许一个一级标题：# Fortify + CodeQL + AI 三方对比审计报告。
- 除报告开头外，不允许再使用一级标题。
- 主章节必须使用上面给出的二级标题，不要自行新增主章节。
- 单个漏洞条目、附录条目统一使用三级标题，不要使用四级标题。
- 禁止使用“同上”“同前”“略”“其余类似”“参见前文”等省略写法。
- 每个主章节先写 2 到 4 句话的结论摘要，再进入表格或明细。
- 不要使用一张超宽总表展示所有明细；但每个问题内部的 Fortify / CodeQL / AI 对比必须使用紧凑表格。
- 总览章节的表格只放统计信息，不要把长路径、长规则、长分析全部塞进总表。
- 单个问题的详细解释放在表格后的“分析结论”和“处理建议”中。
- 每个最终问题必须以 Fortify 主问题组为单位。
- 第 3 章必须完整列出 type_distribution 中的所有 Fortify 漏洞类别，不能只列高危类别。
- 第 8 章要说明 AI 直接审代码结果分别支持哪些 Fortify 主问题组，哪些只是非 Fortify 主线观察项。
- 附录 A 必须覆盖 groups 中的每一个 Fortify 主问题组。每个组按下面格式输出：

  ### A-001 优先级 | 漏洞类型 | 文件名

  | 来源 | 命中状态 | 证据摘要 | 位置 | 结论 |
  | --- | --- | --- | --- | --- |
  | Fortify | 是 | ... | ... | 主问题来源 |
  | CodeQL | 是/否 | ... | ... | 佐证/无佐证 |
  | AI 直接审代码 | 是/否/不确定 | ... | ... | 佐证/需人工确认 |

  分析结论：
  - 用 2 到 4 句话说明三方证据是否互相支持、是否存在误报可能、为什么需要复核。

  处理建议：
  - 给出 1 到 3 条可落地修复或复核建议。

生成前请内部自检：
- 附录 A 条目数必须等于 summary.merged_groups。
- 第 3 章漏洞类别数必须等于 summary.vulnerability_types。
- CodeQL 独有和 AI 独有观察项不能进入最终问题清单。
- 附录 A 编号必须使用三位数字，例如 A-001、A-002，不能写 A-1。
- 附录 A 每个条目都必须独立完整，不能写“同上”。

<merged-analysis.json>
{merged_text}
</merged-analysis.json>

<ai-code-review-result.md>
{ai_review_text}
</ai-code-review-result.md>
        """
    ).strip()

def fallback_report(error: Exception, merged_path: Path, ai_review_path: Path) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return dedent(
        f"""
        # Fortify + CodeQL + AI 三方对比审计报告

        报告生成时间：{now}

        大模型报告生成失败：`{error}`

        已读取输入：
        - `merged-analysis.json`: `{merged_path}`
        - `ai-code-review-result.md`: `{ai_review_path}`

        当前流程没有修改已有 Fortify + CodeQL 合并结果。请检查
        LLM_API_KEY/LLM_API_BASE/LLM_MODEL、DASHSCOPE_API_KEY/DASHSCOPE_API_BASE/DASHSCOPE_MODEL，
        或模型上下文/输出长度限制后重试。
        """
    ).strip()


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def vulnerability_type_checklist(merged_data: dict[str, Any]) -> str:
    rows = []
    for index, item in enumerate(merged_data.get("type_distribution") or [], start=1):
        rows.append(
            f"{index}. {item.get('vulnerability_type')} "
            f"(Fortify={item.get('fortify')}, CodeQL evidence={item.get('codeql_evidence')})"
        )
    return "\n".join(rows) if rows else "未提供漏洞类型分布。"


def group_checklist(groups: list[dict[str, Any]]) -> str:
    rows = []
    for index, group in enumerate(groups, start=1):
        rows.append(
            f"A-{index:03d}. {group.get('priority')} | "
            f"{group.get('vulnerability_type')} | {group.get('file')} | "
            f"Fortify={group.get('fortify_finding_count')} | "
            f"CodeQL evidence={group.get('codeql_evidence_count')}"
        )
    return "\n".join(rows) if rows else "未提供 Fortify 主问题组。"


def compact_group(group: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "id",
        "priority",
        "vulnerability_type",
        "file",
        "lines",
        "rules",
        "severities",
        "fortify_finding_count",
        "codeql_evidence_count",
        "codeql_lines",
        "codeql_rules",
        "messages",
        "fortify_findings",
        "codeql_evidence",
    ]
    return {key: group.get(key) for key in keys if key in group}


def issue_batches(groups: list[dict[str, Any]], batch_size: int) -> list[list[dict[str, Any]]]:
    size = max(batch_size, 1)
    return [groups[index:index + size] for index in range(0, len(groups), size)]


def collect_context_terms(value: Any) -> set[str]:
    terms: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"file", "vulnerability_type"} and item:
                text = str(item)
                terms.add(text)
                terms.add(Path(text).name)
            else:
                terms.update(collect_context_terms(item))
    elif isinstance(value, list):
        for item in value:
            terms.update(collect_context_terms(item))
    return {term for term in terms if len(term) >= 4}


def ai_review_excerpt(ai_review_text: str, context: dict[str, Any], max_chars: int = 6000) -> str:
    terms = collect_context_terms(context)
    if not terms:
        return ai_review_text[:max_chars]

    lines = ai_review_text.splitlines()
    selected: list[str] = []
    used_indexes: set[int] = set()
    lowered_terms = [term.lower() for term in terms]
    for index, line in enumerate(lines):
        lowered_line = line.lower()
        if not any(term in lowered_line for term in lowered_terms):
            continue
        for selected_index in range(max(0, index - 4), min(len(lines), index + 8)):
            if selected_index not in used_indexes:
                selected.append(lines[selected_index])
                used_indexes.add(selected_index)
        if len("\n".join(selected)) >= max_chars:
            break

    excerpt = "\n".join(selected).strip()
    if not excerpt:
        return (
            "AI 直接审代码结果中没有匹配当前 Fortify 文件或漏洞类型的片段。"
            "除非结构化上下文另有明确证据，否则应将 AI 佐证结论标记为不确定。"
        )
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars] + "\n...[AI review excerpt truncated]"
    return excerpt


def report_header(merged_data: dict[str, Any], project_dir: Path) -> str:
    summary = merged_data.get("summary") or {}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return dedent(
        f"""
        # Fortify + CodeQL + AI 直接审代码三方对比审计报告

        报告生成时间：{now}

        项目路径：`{project_dir}`

        分析口径：Fortify 主问题组决定最终问题全集，CodeQL 和 AI 直接审代码结果仅作为佐证。

        关键统计：Fortify 原始发现 {summary.get("fortify_total_findings")} 条，
        CodeQL 原始发现 {summary.get("codeql_total_findings")} 条，
        Fortify 主问题组 {summary.get("merged_groups")} 个，
        CodeQL 佐证发现 {summary.get("codeql_evidence_findings")} 条，
        CodeQL 独有忽略发现 {summary.get("ignored_codeql_findings")} 条。
        """
    ).strip()


def safe_max_tokens(requested: int) -> tuple[int, str | None]:
    if requested <= 0:
        return 4000, "配置的 max_tokens 小于等于 0，已改用每次大模型调用 4000。"
    if requested > 8000:
        return 4000, (
            f"配置的 max_tokens={requested} 对单次 DashScope 调用过高；"
            "已改用每次大模型调用 4000，并通过多次调用生成报告。"
        )
    return requested, None


async def call_report_llm(
    stage: str,
    instruction: str,
    context: dict[str, Any],
    ai_review_text: str,
    temperature: float,
    max_tokens: int,
    progress_callback: Callable[[str], None] | None = None,
) -> tuple[str, str | None]:
    excerpt = ai_review_excerpt(ai_review_text, context)
    prompt = dedent(
        f"""
        请使用简体中文 Markdown 编写本报告片段。
        只输出最终报告正文，不要输出推理过程、计划过程或分析笔记。

        任务要求：
        {instruction}

        来自 merged-analysis.json 的结构化上下文：
        {json_text(context)}

        AI 直接审代码 Markdown 中与当前上下文相关的片段：
        <ai-code-review-result-excerpt>
        {excerpt}
        </ai-code-review-result-excerpt>
        """
    ).strip()

    attempts = []
    for tokens in (max_tokens, 4000, 3000):
        if tokens > 0 and tokens not in attempts:
            attempts.append(tokens)

    last_error: Exception | None = None
    for tokens in attempts:
        try:
            if progress_callback:
                progress_callback(f"{stage}: 请求大模型，max_tokens={tokens}")
            result = await chat_completion(
                [
                    {"role": "system", "content": build_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,
                max_tokens=tokens,
            )
            if progress_callback:
                progress_callback(f"{stage}: 完成")
            warning = None
            if tokens != max_tokens:
                warning = f"某个报告片段已使用 max_tokens={tokens} 重试。"
            return result.strip(), warning
        except Exception as exc:
            last_error = exc

    raise RuntimeError(f"LLM report part generation failed: {last_error}")


async def generate_detailed_report(
    project_dir: Path,
    merged_data: dict[str, Any],
    ai_review_text: str,
    temperature: float,
    max_tokens: int,
    progress_callback: Callable[[str], None] | None = None,
) -> tuple[str, list[str]]:
    groups = [compact_group(group) for group in (merged_data.get("groups") or [])]
    batch_size = 4
    warnings: list[str] = []
    effective_tokens, token_warning = safe_max_tokens(max_tokens)
    if token_warning:
        warnings.append(token_warning)

    parts = [report_header(merged_data, project_dir)]
    if progress_callback:
        progress_callback(
            f"starting detailed multi-call report: {len(groups)} Fortify groups, "
            f"batch_size={batch_size}, per_call_max_tokens={effective_tokens}"
        )

    overview_context = {
        "project_path": merged_data.get("project_path"),
        "merge_policy": merged_data.get("merge_policy"),
        "tool_summaries": merged_data.get("tool_summaries"),
        "summary": merged_data.get("summary"),
        "type_distribution": merged_data.get("type_distribution"),
        "direct_overlap_groups": merged_data.get("direct_overlap_groups"),
        "ignored_codeql_summary": merged_data.get("ignored_codeql_summary"),
    }
    text, warning = await call_report_llm(
        "sections 1-4",
        f"""
        只生成第 1 到第 4 章：
        1. 扫描与输入概览
        2. 三方合并规则与风险口径
        3. Fortify 主问题全集统计
        4. 三方重合与差异分析

        第 3 章是必填章节，必须包含完整的 Fortify 漏洞类别表。
        表格必须包含下面这些漏洞类别，不能遗漏：

        {vulnerability_type_checklist(merged_data)}

        使用可读性好的表格，列名建议为：
        漏洞类别 | Fortify 发现数 | CodeQL 佐证数 | 最终处理口径。
        不能只列高危类别。
        """,
        overview_context,
        ai_review_text,
        temperature,
        effective_tokens,
        progress_callback,
    )
    parts.append(text)
    if warning:
        warnings.append(warning)

    review_context = {
        "summary": merged_data.get("summary"),
        "deduplication_candidates": merged_data.get("deduplication_candidates"),
        "false_positive_review_candidates": merged_data.get("false_positive_review_candidates"),
        "high_priority_groups": merged_data.get("high_priority_groups"),
    }
    text, warning = await call_report_llm(
        "sections 5-8",
        """
        只生成第 5 到第 8 章：
        5. 去重分析
        6. 疑似误报与需人工确认项
        7. P0/P1 优先复核清单
        8. AI 直接审代码结果对 Fortify 主线的补充判断

        必须保持 Fortify 作为最终问题来源。CodeQL 和 AI 直接审代码结果仅作为佐证。
        对每个关键项说明为什么需要复核、合并或人工确认。

        只要讨论某一个具体 Fortify 问题组，就必须使用下面这种三方对比表：

        | 来源 | 是否命中 | 证据/规则 | 行号/位置 | 结论 |
        | --- | --- | --- | --- | --- |
        | Fortify | 是 | ... | ... | 主问题来源 |
        | CodeQL | 是/否 | ... | ... | 佐证/无佐证 |
        | AI 直接审代码 | 是/否/不确定 | ... | ... | 佐证/需人工确认 |

        P0/P1 每一项都必须有这个表格。疑似误报/人工确认项每一项也必须有这个表格。
        不要用纯段落替代表格。
        """,
        review_context,
        ai_review_text,
        temperature,
        effective_tokens,
        progress_callback,
    )
    parts.append(text)
    if warning:
        warnings.append(warning)

    remediation_context = {
        "summary": merged_data.get("summary"),
        "type_distribution": merged_data.get("type_distribution"),
        "group_index": [
            {
                "priority": group.get("priority"),
                "vulnerability_type": group.get("vulnerability_type"),
                "file": group.get("file"),
                "fortify_finding_count": group.get("fortify_finding_count"),
                "codeql_evidence_count": group.get("codeql_evidence_count"),
            }
            for group in groups
        ],
    }
    text, warning = await call_report_llm(
        "sections 9-10",
        f"""
        只生成第 9 和第 10 章：
        9. 按漏洞类型的修复建议
        10. 给 AI Agent 的落地处理建议

        第 9 章必须覆盖下面每一种漏洞类型，每种类型单独一个小节。
        不要跳过低风险类别，也不要跳过单工具发现类别：

        {vulnerability_type_checklist(merged_data)}

        修复建议必须具体，并且要和上下文中的文件、漏洞类型关联。
        """,
        remediation_context,
        ai_review_text,
        temperature,
        effective_tokens,
        progress_callback,
    )
    parts.append(text)
    if warning:
        warnings.append(warning)

    parts.append("## 附录 A：Fortify 主问题组三方明细")
    for batch_index, batch in enumerate(issue_batches(groups, batch_size), start=1):
        start = (batch_index - 1) * batch_size + 1
        end = start + len(batch) - 1
        text, warning = await call_report_llm(
            f"appendix A entries A-{start:03d} to A-{end:03d}",
            f"""
            只生成附录 A 中 A-{start:03d} 到 A-{end:03d} 的条目。
            必须输出正好 {len(batch)} 个条目，提供的每个 Fortify 组都要有一个条目。
            不要遗漏任何组。

            本批次必须覆盖的 Fortify 组：
            {group_checklist(batch)}

            每个组必须使用以下格式：

            #### A-NNN 优先级 | 漏洞类型 | 文件名

            | 来源 | 是否命中 | 证据/规则 | 行号/位置 | 结论 |
            | --- | --- | --- | --- | --- |
            | Fortify | 是 | ... | ... | 主问题来源 |
            | CodeQL | 是/否 | ... | ... | 佐证/无佐证 |
            | AI 直接审代码 | 是/否/不确定 | ... | ... | 佐证/需人工确认 |

            表格后补充 1 到 3 条简洁处理建议。
            """,
            {"groups": batch},
            ai_review_text,
            temperature,
            effective_tokens,
            progress_callback,
        )
        parts.append(text)
        if warning:
            warnings.append(warning)

    text, warning = await call_report_llm(
        "appendix B",
        """
        只生成附录 B：
        附录 B：非 Fortify 主线观察项

        从 AI 直接审代码结果中提取无法明确匹配 Fortify 主问题组的观察项。
        必须明确说明这些观察项默认不纳入最终漏洞清单。
        不要把这些观察项加入附录 A。
        """,
        {
            "summary": merged_data.get("summary"),
            "merge_policy": merged_data.get("merge_policy"),
            "fortify_group_index": [
                {
                    "vulnerability_type": group.get("vulnerability_type"),
                    "file": group.get("file"),
                }
                for group in groups
            ],
        },
        ai_review_text,
        temperature,
        effective_tokens,
        progress_callback,
    )
    parts.append(text)
    if warning:
        warnings.append(warning)

    return "\n\n".join(parts), warnings


async def generate_three_way_report(request: ThreeWayReportRequest) -> ThreeWayReportResult:
    project_dir = Path(request.project_path).expanduser().resolve()
    merged_path = resolve_path(project_dir, request.merged_input, default_merged_path(project_dir))
    ai_review_path = resolve_path(project_dir, request.ai_review_input, default_ai_review_path(project_dir))
    output_path = resolve_path(project_dir, request.report_output, default_report_path(project_dir))

    if not merged_path.exists():
        raise FileNotFoundError(f"未找到 merged-analysis.json：{merged_path}")
    if not ai_review_path.exists():
        raise FileNotFoundError(f"未找到 AI 代码审查 Markdown：{ai_review_path}")

    merged_data = read_json_auto(merged_path)
    merged_text = json.dumps(merged_data, ensure_ascii=False, indent=2)
    ai_review_text = read_text_auto(ai_review_path)

    warnings: list[str] = []
    merged_text, merged_warning = maybe_limit_text(
        merged_text,
        request.max_merged_chars,
        "merged-analysis.json",
    )
    ai_review_text, ai_warning = maybe_limit_text(
        ai_review_text,
        request.max_ai_review_chars,
        "ai-code-review-result.md",
    )
    if merged_warning:
        warnings.append(merged_warning)
    if ai_warning:
        warnings.append(ai_warning)

    messages = [
        {"role": "system", "content": build_system_prompt()},
        {
            "role": "user",
            "content": build_user_prompt(
                project_dir,
                merged_path,
                merged_text,
                ai_review_path,
                ai_review_text,
                warnings,
            ),
        },
    ]

    warning = "; ".join(warnings) if warnings else None
    max_tokens = request.max_tokens
    try:
        if request.progress_callback:
            token_text = str(max_tokens) if max_tokens is not None else "服务商默认值"
            request.progress_callback(f"流式生成单次三方报告，max_tokens={token_text}")
        report = await chat_completion_stream(
            messages,
            temperature=request.temperature,
            max_tokens=max_tokens,
            progress_callback=request.progress_callback,
        )
        if request.progress_callback:
            request.progress_callback("单次三方报告流式生成完成")
    except Exception as exc:
        report = fallback_report(exc, merged_path, ai_review_path)
        warning = f"已使用大模型报告兜底内容：{exc}"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report.strip() + "\n", encoding="utf-8-sig")

    return ThreeWayReportResult(
        report_path=str(output_path),
        merged_path=str(merged_path),
        ai_review_path=str(ai_review_path),
        warning=warning,
    )
