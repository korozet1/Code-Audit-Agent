from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any


TYPE_PATTERNS = [
    (("xxe", "xml external entity", "external entity", "xml entity"), "XXE/XML 实体注入"),
    (("xss", "cross-site scripting", "cross site scripting"), "XSS"),
    (("ssrf", "server-side request forgery", "server side request forgery"), "SSRF"),
    (
        (
            "sql injection",
            "sqli",
            "mybatis",
            "jdbc",
            "sql 注入",
            "query built from user-controlled",
            "database query built from user-controlled",
        ),
        "SQL 注入",
    ),
    (
        (
            "path traversal",
            "path injection",
            "file path",
            "path expression",
            "zip slip",
            "路径遍历",
        ),
        "路径遍历/文件路径控制",
    ),
    (
        (
            "command injection",
            "command execution",
            "runtime.exec",
            "uncontrolled command line",
            "命令",
        ),
        "命令执行/命令注入",
    ),
    (("deserialization", "deserialize", "反序列化"), "反序列化"),
    (("open redirect", "redirect", "forward", "重定向", "转发"), "开放重定向/转发"),
    (("response splitting", "crlf", "http response splitting"), "HTTP 响应拆分/CRLF"),
    (("log forging", "log injection", "日志"), "日志注入"),
    (("hardcoded password", "password management", "credential", "secret", "密码"), "敏感信息/密码管理"),
    (("information exposure", "information leak", "privacy", "信息泄露"), "信息泄露"),
    (("cookie", "samesite", "httponly", "secure flag"), "Cookie 安全配置"),
    (("template injection", "expression language", "spel", "ognl", "表达式"), "表达式/模板注入"),
    (("file upload", "unrestricted upload", "multipart", "上传"), "文件上传风险"),
    (("actuator", "spring boot actuator"), "Spring Boot Actuator 暴露"),
    (("resource leak", "close", "资源泄露"), "资源泄露"),
]

HIGH_RISK_TYPES = {
    "SQL 注入",
    "命令执行/命令注入",
    "反序列化",
    "SSRF",
    "XXE/XML 实体注入",
    "路径遍历/文件路径控制",
    "XSS",
    "文件上传风险",
}

MEDIUM_SEVERITIES = {"MEDIUM", "WARNING"}
HIGH_SEVERITIES = {"CRITICAL", "HIGH", "ERROR"}
FALSE_POSITIVE_HINT_TYPES = {
    "代码质量/最佳实践",
    "日志注入",
    "资源泄露",
    "Cookie 安全配置",
    "信息泄露",
}


def finding_text(finding: dict[str, Any]) -> str:
    fields = [
        finding.get("rule_id"),
        finding.get("rule_name"),
        finding.get("rule_description"),
        finding.get("category"),
        finding.get("message"),
    ]
    return " ".join(str(item) for item in fields if item).lower()


def normalize_vulnerability_type(finding: dict[str, Any]) -> str:
    text = finding_text(finding)
    for patterns, label in TYPE_PATTERNS:
        if any(pattern in text for pattern in patterns):
            return label
    category = finding.get("category")
    if category:
        return str(category)
    return str(finding.get("rule_name") or finding.get("rule_id") or "未分类问题")


def finding_file(finding: dict[str, Any]) -> str:
    return str(finding.get("file") or finding.get("file_path") or "<unknown>")


def finding_line(finding: dict[str, Any]) -> int | None:
    line = finding.get("start_line")
    if line is None:
        return None
    try:
        return int(line)
    except (TypeError, ValueError):
        return None


def normalize_severity(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


def priority_for_group(vulnerability_type: str, severities: set[str], sources: set[str]) -> str:
    if len(sources) > 1:
        return "P0-双工具确认"
    if vulnerability_type in HIGH_RISK_TYPES and severities & HIGH_SEVERITIES:
        return "P0-高危类型"
    if severities & HIGH_SEVERITIES:
        return "P1-高风险"
    if vulnerability_type in HIGH_RISK_TYPES or severities & MEDIUM_SEVERITIES:
        return "P2-中风险"
    return "P3-低风险/质量"


def tool_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool_name": payload.get("tool_name") or payload.get("tool", {}).get("name"),
        "status": payload.get("status"),
        "generated_at": payload.get("generated_at"),
        "project_path": payload.get("project_path"),
        "raw_report_path": payload.get("raw_report_path"),
        "total_findings": payload.get("total_findings"),
        "returned_findings": payload.get("returned_findings"),
        "severity_count": payload.get("severity_count") or {},
    }


def scan_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = payload.get("findings")
    return findings if isinstance(findings, list) else []


def finding_source(finding: dict[str, Any]) -> str:
    return str(finding.get("tool_name") or finding.get("source") or "unknown")


def rule_name(finding: dict[str, Any]) -> str | None:
    value = finding.get("rule_name") or finding.get("rule_id")
    return str(value) if value else None


def finding_message(finding: dict[str, Any]) -> str | None:
    value = finding.get("message") or finding.get("rule_description")
    return str(value) if value else None


def compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id"),
        "tool_name": finding_source(finding),
        "rule_id": finding.get("rule_id"),
        "rule_name": rule_name(finding),
        "severity": normalize_severity(finding.get("severity")),
        "message": finding_message(finding),
        "file": finding_file(finding),
        "start_line": finding_line(finding),
        "start_col": finding.get("start_col"),
        "end_line": finding.get("end_line"),
        "end_col": finding.get("end_col"),
        "category": finding.get("category"),
    }


def build_group_payload(
    vulnerability_type: str,
    file_path: str,
    fortify_findings: list[dict[str, Any]],
    codeql_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    codeql_evidence = codeql_evidence or []
    evidence_findings = fortify_findings + codeql_evidence
    sources = {"fortify"}
    if codeql_evidence:
        sources.add("codeql")
    severities = {normalize_severity(item.get("severity")) for item in fortify_findings}
    codeql_severities = {normalize_severity(item.get("severity")) for item in codeql_evidence}
    lines = sorted({line for item in fortify_findings if (line := finding_line(item)) is not None})
    codeql_lines = sorted({line for item in codeql_evidence if (line := finding_line(item)) is not None})
    rules = sorted({
        rule
        for item in fortify_findings
        if (rule := rule_name(item))
    })
    codeql_rules = sorted({
        rule
        for item in codeql_evidence
        if (rule := rule_name(item))
    })
    messages = []
    for item in evidence_findings:
        message = finding_message(item)
        if message and message not in messages:
            messages.append(message)

    return {
        "priority": priority_for_group(vulnerability_type, severities, sources),
        "vulnerability_type": vulnerability_type,
        "file": file_path,
        "sources": sorted(sources),
        "severities": sorted(severities),
        "codeql_severities": sorted(codeql_severities),
        "lines": lines,
        "codeql_lines": codeql_lines,
        "rules": rules[:20],
        "codeql_rules": codeql_rules[:20],
        "messages": messages[:10],
        "finding_count": len(fortify_findings),
        "fortify_finding_count": len(fortify_findings),
        "codeql_evidence_count": len(codeql_evidence),
        "has_codeql_evidence": bool(codeql_evidence),
        "fortify_findings": [compact_finding(item) for item in fortify_findings],
        "codeql_evidence": [compact_finding(item) for item in codeql_evidence],
    }


def duplicate_reason(group: dict[str, Any]) -> str | None:
    if group["fortify_finding_count"] <= 1:
        return None
    if len(group["rules"]) > 1:
        return "Fortify 在同一文件上命中多个相近规则，可能存在规则粒度重复。"
    return "Fortify 在同一漏洞类型和同一文件存在多条结果，可能是多入口或同一问题的多行重复。"


def false_positive_reason(group: dict[str, Any]) -> str | None:
    if len(group["sources"]) > 1:
        return None
    if any("password in comment" in rule.lower() for rule in group["rules"]):
        return "Fortify 命中的是注释中的 password 字样，通常需要人工确认是否只是示例/注释文本。"
    if group["vulnerability_type"] in FALSE_POSITIVE_HINT_TYPES:
        return "该类型常需要结合运行上下文确认，且当前缺少 CodeQL 佐证，建议复核可达性和真实影响面。"
    if not group["lines"]:
        return "结果缺少明确行号，定位证据不足，建议人工复核。"
    if group["priority"].startswith("P3"):
        return "优先级较低，更可能是质量建议或最佳实践问题，需要和漏洞类问题分开处理。"
    return None


def build_deduplication_candidates(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = []
    for group in groups:
        reason = duplicate_reason(group)
        if not reason:
            continue
        candidates.append({
            "vulnerability_type": group["vulnerability_type"],
            "file": group["file"],
            "sources": group["sources"],
            "rules": group["rules"],
            "lines": group["lines"],
            "finding_count": group["finding_count"],
            "fortify_finding_count": group["fortify_finding_count"],
            "codeql_evidence_count": group["codeql_evidence_count"],
            "dedup_suggestion": "review_as_one_issue_group",
            "reason": reason,
        })
    return candidates


def build_false_positive_candidates(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = []
    for group in groups:
        reason = false_positive_reason(group)
        if not reason:
            continue
        candidates.append({
            "priority": group["priority"],
            "vulnerability_type": group["vulnerability_type"],
            "file": group["file"],
            "sources": group["sources"],
            "rules": group["rules"],
            "lines": group["lines"],
            "finding_count": group["finding_count"],
            "fortify_finding_count": group["fortify_finding_count"],
            "codeql_evidence_count": group["codeql_evidence_count"],
            "review_suggestion": "needs_manual_or_llm_source_review",
            "reason": reason,
        })
    return candidates


def priority_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    priority_order = {
        "P0-双工具确认": 0,
        "P0-高危类型": 1,
        "P1-高风险": 2,
        "P2-中风险": 3,
        "P3-低风险/质量": 4,
    }
    return (
        priority_order.get(item["priority"], 99),
        str(item.get("file") or ""),
        str(item.get("vulnerability_type") or ""),
    )


def merge_scan_results(
    project_path: str,
    codeql_result: dict[str, Any] | None,
    fortify_result: dict[str, Any] | None,
) -> dict[str, Any]:
    fortify_findings = scan_findings(fortify_result or {})
    codeql_findings = scan_findings(codeql_result or {})

    fortify_grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for finding in fortify_findings:
        vulnerability_type = normalize_vulnerability_type(finding)
        file_path = finding_file(finding)
        fortify_grouped[(vulnerability_type, file_path)].append(finding)

    codeql_evidence_by_group: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    ignored_codeql_findings: list[dict[str, Any]] = []
    ignored_codeql_type_counts: dict[str, int] = defaultdict(int)
    for finding in codeql_findings:
        vulnerability_type = normalize_vulnerability_type(finding)
        file_path = finding_file(finding)
        group_key = (vulnerability_type, file_path)
        if group_key in fortify_grouped:
            codeql_evidence_by_group[group_key].append(finding)
        else:
            ignored_codeql_findings.append(finding)
            ignored_codeql_type_counts[vulnerability_type] += 1

    groups = [
        build_group_payload(
            vulnerability_type,
            file_path,
            findings,
            codeql_evidence_by_group.get((vulnerability_type, file_path), []),
        )
        for (vulnerability_type, file_path), findings in fortify_grouped.items()
    ]
    groups.sort(key=priority_sort_key)

    type_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    type_sources: dict[str, set[str]] = defaultdict(set)
    for group in groups:
        vulnerability_type = group["vulnerability_type"]
        type_counts[vulnerability_type]["fortify"] += group["fortify_finding_count"]
        type_counts[vulnerability_type]["codeql_evidence"] += group["codeql_evidence_count"]
        type_sources[vulnerability_type].add("fortify")
        if group["codeql_evidence_count"]:
            type_sources[vulnerability_type].add("codeql")

    type_distribution = []
    for vulnerability_type, counts in type_counts.items():
        fortify_count = counts.get("fortify", 0)
        codeql_count = counts.get("codeql_evidence", 0)
        sources = sorted(type_sources[vulnerability_type])
        type_distribution.append({
            "vulnerability_type": vulnerability_type,
            "fortify": fortify_count,
            "codeql": codeql_count,
            "codeql_evidence": codeql_count,
            "raw_count": fortify_count,
            "sources": sources,
        })
    type_distribution.sort(key=lambda item: item["fortify"], reverse=True)

    direct_overlap_groups = [item for item in groups if item["has_codeql_evidence"]]
    high_priority_groups = [
        item for item in groups if item["priority"].startswith("P0") or item["priority"].startswith("P1")
    ]
    deduplication_candidates = build_deduplication_candidates(groups)
    false_positive_review_candidates = build_false_positive_candidates(groups)
    matched_codeql_findings = sum(item["codeql_evidence_count"] for item in groups)

    return {
        "project_path": str(Path(project_path).resolve()),
        "merge_policy": {
            "primary_tool": "fortify",
            "evidence_tool": "codeql",
            "group_key": "normalized_vulnerability_type + file",
            "codeql_unique_policy": "ignored",
            "description": "Fortify findings define the final issue set. CodeQL findings are retained only when they match a Fortify group by normalized vulnerability type and file.",
        },
        "tool_summaries": {
            "codeql": tool_summary(codeql_result or {}),
            "fortify": tool_summary(fortify_result or {}),
        },
        "summary": {
            "raw_total_findings": len(fortify_findings) + len(codeql_findings),
            "fortify_total_findings": len(fortify_findings),
            "codeql_total_findings": len(codeql_findings),
            "codeql_evidence_findings": matched_codeql_findings,
            "ignored_codeql_findings": len(ignored_codeql_findings),
            "merged_groups": len(groups),
            "vulnerability_types": len(type_distribution),
            "direct_overlap_groups": len(direct_overlap_groups),
            "type_overlap_count": sum(1 for sources in type_sources.values() if "codeql" in sources),
            "high_priority_groups": len(high_priority_groups),
            "deduplication_candidates": len(deduplication_candidates),
            "false_positive_review_candidates": len(false_positive_review_candidates),
            "files_involved": len({item["file"] for item in groups if item["file"] != "<unknown>"}),
        },
        "ignored_codeql_summary": {
            "total_findings": len(ignored_codeql_findings),
            "type_count": dict(sorted(ignored_codeql_type_counts.items())),
        },
        "type_distribution": type_distribution,
        "direct_overlap_groups": direct_overlap_groups,
        "high_priority_groups": high_priority_groups,
        "deduplication_candidates": deduplication_candidates,
        "false_positive_review_candidates": false_positive_review_candidates,
        "groups": groups,
    }


__all__ = ["merge_scan_results", "normalize_vulnerability_type"]
