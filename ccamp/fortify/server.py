from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree as ET

from fastmcp import FastMCP

from ccamp.shared.constants import LOCAL_NO_PROXY
from ccamp.shared.env import get_env_int, get_required_env, load_project_env
from ccamp.shared.paths import resolve_project_path
from ccamp.shared.report_schema import normalize_scan_result
from ccamp.shared.stats import count_by_severity
from ccamp.shared.text import tail_text


mcp = FastMCP("fortify_mcp")

os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

load_project_env()

FORTIFY_BIN = "sourceanalyzer"
DEFAULT_OUTPUT_DIR = "reports"
DEFAULT_FPR_NAME = "fortify.fpr"
DEFAULT_JSON_NAME = "fortify.json"
DEFAULT_CSV_NAME = "fortify.csv"
DEFAULT_FVDL_NAME = "audit.fvdl"


def find_sourceanalyzer_binary() -> str:
    configured = os.getenv("FORTIFY_SOURCEANALYZER_BIN") or os.getenv("FORTIFY_BIN")
    if configured and Path(configured).expanduser().exists():
        return str(Path(configured).expanduser().resolve())

    fortify_home = os.getenv("FORTIFY_HOME")
    if fortify_home:
        candidate = Path(fortify_home).expanduser() / "bin" / "sourceanalyzer.exe"
        if candidate.exists():
            return str(candidate.resolve())

    for candidate in [FORTIFY_BIN, "sourceanalyzer.exe"]:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    raise RuntimeError(
        "Fortify sourceanalyzer executable not found. Make sure "
        "`sourceanalyzer.exe -version` works, or set FORTIFY_SOURCEANALYZER_BIN."
    )


def fortify_home_from_binary(binary: str) -> Path | None:
    path = Path(binary).expanduser().resolve()
    if path.parent.name.lower() == "bin":
        return path.parent.parent
    return None


def installed_rules_dir() -> Path | None:
    configured = os.getenv("FORTIFY_INSTALLED_RULES_DIR")
    if configured:
        return Path(configured).expanduser().resolve()

    home = fortify_home_from_binary(find_sourceanalyzer_binary())
    if not home:
        return None
    return home / "Core" / "config" / "rules"


def count_rules_files(rules_dir: Path | None) -> int:
    if not rules_dir or not rules_dir.exists():
        return 0
    return sum(1 for path in rules_dir.iterdir() if path.suffix.lower() in {".bin", ".xml"})


def ensure_rules_available() -> None:
    rules_dir = installed_rules_dir()
    if count_rules_files(rules_dir) > 0:
        return

    rules_text = str(rules_dir) if rules_dir else "<unknown>"
    raise RuntimeError(
        "No Fortify rules files found. Copy legal Fortify rule files into "
        f"{rules_text}, or set FORTIFY_INSTALLED_RULES_DIR to the active rules directory."
    )


def default_build_id(project_dir: Path) -> str:
    return project_dir.name.replace(" ", "_") or "fortify_scan"


def default_source_path(project_dir: Path) -> Path:
    for candidate in [project_dir / "src", project_dir / "source", project_dir / "app"]:
        if candidate.exists() and candidate.is_dir():
            return candidate.resolve()
    return project_dir.resolve()


def resolve_output_paths(
    project_dir: Path,
    output_dir: str | None,
    fpr_file: str | None,
    json_file: str | None,
    csv_file: str | None,
    fvdl_file: str | None,
) -> dict[str, Path]:
    report_dir = Path(output_dir).expanduser() if output_dir else project_dir / DEFAULT_OUTPUT_DIR
    if not report_dir.is_absolute():
        report_dir = project_dir / report_dir
    report_dir = report_dir.resolve()

    def resolve_file(value: str | None, default_name: str) -> Path:
        path = Path(value).expanduser() if value else report_dir / default_name
        if not path.is_absolute():
            path = project_dir / path
        return path.resolve()

    return {
        "report_dir": report_dir,
        "fpr": resolve_file(fpr_file, DEFAULT_FPR_NAME),
        "json": resolve_file(json_file, DEFAULT_JSON_NAME),
        "csv": resolve_file(csv_file, DEFAULT_CSV_NAME),
        "fvdl": resolve_file(fvdl_file, DEFAULT_FVDL_NAME),
    }


def build_clean_command(build_id: str) -> list[str]:
    return [find_sourceanalyzer_binary(), "-b", build_id, "-clean"]


def build_translate_command(
    build_id: str,
    project_dir: Path,
    source_path: str | None,
    build_command: list[str] | None,
) -> list[str]:
    command = [find_sourceanalyzer_binary(), "-b", build_id]
    if build_command:
        return command + build_command

    target = Path(source_path).expanduser() if source_path else default_source_path(project_dir)
    if not target.is_absolute():
        target = project_dir / target
    return command + [str(target.resolve())]


def build_scan_command(build_id: str, fpr_file: Path) -> list[str]:
    return [find_sourceanalyzer_binary(), "-b", build_id, "-scan", "-f", str(fpr_file)]


def run_command(
    command: list[str],
    cwd: Path,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout_seconds,
    )


def extract_fvdl(fpr_file: Path, fvdl_file: Path) -> None:
    with zipfile.ZipFile(fpr_file) as archive:
        with archive.open("audit.fvdl") as source:
            fvdl_file.parent.mkdir(parents=True, exist_ok=True)
            fvdl_file.write_bytes(source.read())


def xml_text(node: ET.Element, path: str, namespace: dict[str, str]) -> str | None:
    found = node.find(path, namespace)
    if found is None or found.text is None:
        return None
    value = found.text.strip()
    return value or None


def float_value(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def int_value(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def severity_label(severity: float | None) -> str:
    if severity is None:
        return "UNKNOWN"
    if severity >= 4.0:
        return "CRITICAL"
    if severity >= 3.0:
        return "HIGH"
    if severity >= 2.0:
        return "MEDIUM"
    if severity >= 1.0:
        return "LOW"
    return "INFO"


def to_project_relative(project_dir: Path, absolute_file: Path | None, raw_path: str | None) -> str | None:
    if absolute_file:
        try:
            return str(absolute_file.resolve().relative_to(project_dir.resolve())).replace("\\", "/")
        except ValueError:
            return str(absolute_file)
    return raw_path


def absolute_location(
    project_dir: Path,
    source_base_path: str | None,
    raw_path: str | None,
) -> Path | None:
    if not raw_path:
        return None

    raw = Path(raw_path)
    if raw.is_absolute():
        return raw

    if source_base_path:
        base = Path(source_base_path)
        if base.is_absolute():
            return (base / PurePosixPath(raw_path)).resolve()

    return (project_dir / PurePosixPath(raw_path)).resolve()


def parse_fvdl(fvdl_file: Path, project_dir: Path) -> list[dict[str, Any]]:
    tree = ET.parse(fvdl_file)
    root = tree.getroot()
    namespace_uri = root.tag.split("}", 1)[0].strip("{") if root.tag.startswith("{") else ""
    ns = {"f": namespace_uri} if namespace_uri else {}
    prefix = "f:" if namespace_uri else ""
    source_base_path = xml_text(root, f"{prefix}Build/{prefix}SourceBasePath", ns)

    findings: list[dict[str, Any]] = []
    for vulnerability in root.findall(f".//{prefix}Vulnerability", ns):
        class_id = xml_text(vulnerability, f"{prefix}ClassInfo/{prefix}ClassID", ns)
        kingdom = xml_text(vulnerability, f"{prefix}ClassInfo/{prefix}Kingdom", ns)
        vuln_type = xml_text(vulnerability, f"{prefix}ClassInfo/{prefix}Type", ns)
        subtype = xml_text(vulnerability, f"{prefix}ClassInfo/{prefix}Subtype", ns)
        analyzer = xml_text(vulnerability, f"{prefix}ClassInfo/{prefix}AnalyzerName", ns)
        instance_id = xml_text(vulnerability, f"{prefix}InstanceInfo/{prefix}InstanceID", ns)
        severity = float_value(
            xml_text(vulnerability, f"{prefix}InstanceInfo/{prefix}InstanceSeverity", ns)
        )
        confidence = float_value(
            xml_text(vulnerability, f"{prefix}InstanceInfo/{prefix}Confidence", ns)
        )

        location = vulnerability.find(f".//{prefix}SourceLocation", ns)
        raw_file = location.get("path") if location is not None else None
        absolute_file = absolute_location(project_dir, source_base_path, raw_file)
        file_value = to_project_relative(project_dir, absolute_file, raw_file)
        start_line = int_value(location.get("line")) if location is not None else None
        end_line = int_value(location.get("lineEnd")) if location is not None else None
        start_col = int_value(location.get("colStart")) if location is not None else None
        end_col = int_value(location.get("colEnd")) if location is not None else None

        name = ": ".join(part for part in [vuln_type, subtype] if part)
        findings.append({
            "rule_id": class_id,
            "instance_id": instance_id,
            "name": name or class_id,
            "description": name or None,
            "severity": severity_label(severity),
            "fortify_severity": severity,
            "confidence": confidence,
            "message": name or None,
            "file": file_value,
            "absolute_file": str(absolute_file) if absolute_file else None,
            "start_line": start_line,
            "start_col": start_col,
            "end_line": end_line,
            "end_col": end_col,
            "kingdom": kingdom,
            "type": vuln_type,
            "subtype": subtype,
            "analyzer": analyzer,
            "category": kingdom,
            "technology": [],
            "cwe": [],
            "owasp": [],
            "impact": None,
            "likelihood": None,
            "vulnerability_class": [vuln_type] if vuln_type else [],
            "references": [],
            "source": "fortify",
        })

    return findings


def write_json(findings: list[dict[str, Any]], json_file: Path) -> None:
    json_file.parent.mkdir(parents=True, exist_ok=True)
    json_file.write_text(
        json.dumps(findings, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )


def write_csv(findings: list[dict[str, Any]], csv_file: Path) -> None:
    csv_file.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "rule_id",
        "instance_id",
        "name",
        "severity",
        "fortify_severity",
        "confidence",
        "file",
        "start_line",
        "start_col",
        "end_line",
        "end_col",
        "kingdom",
        "type",
        "subtype",
        "analyzer",
        "message",
    ]
    with csv_file.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)


def export_fpr_to_reports(
    fpr_file: Path,
    project_dir: Path,
    json_file: Path,
    csv_file: Path,
    fvdl_file: Path,
) -> list[dict[str, Any]]:
    extract_fvdl(fpr_file, fvdl_file)
    findings = parse_fvdl(fvdl_file, project_dir)
    write_json(findings, json_file)
    write_csv(findings, csv_file)
    return findings


@mcp.tool
def get_fortify_command_preview(
    project_path: str,
    build_id: str | None = None,
    source_path: str | None = None,
    build_command: list[str] | None = None,
    output_dir: str | None = None,
    fpr_file: str | None = None,
    json_file: str | None = None,
    csv_file: str | None = None,
    fvdl_file: str | None = None,
) -> dict[str, Any]:
    project_dir = resolve_project_path(project_path)
    resolved_build_id = build_id or default_build_id(project_dir)
    paths = resolve_output_paths(project_dir, output_dir, fpr_file, json_file, csv_file, fvdl_file)
    rules_dir = installed_rules_dir()

    return {
        "project_path": str(project_dir),
        "sourceanalyzer_binary": find_sourceanalyzer_binary(),
        "fortify_rules_dir": str(rules_dir) if rules_dir else None,
        "fortify_rules_count": count_rules_files(rules_dir),
        "build_id": resolved_build_id,
        "fpr_file": str(paths["fpr"]),
        "json_file": str(paths["json"]),
        "csv_file": str(paths["csv"]),
        "fvdl_file": str(paths["fvdl"]),
        "clean_command": build_clean_command(resolved_build_id),
        "translate_command": build_translate_command(
            resolved_build_id,
            project_dir,
            source_path,
            build_command,
        ),
        "scan_command": build_scan_command(resolved_build_id, paths["fpr"]),
    }


@mcp.tool
def scan_project_with_fortify(
    project_path: str,
    build_id: str | None = None,
    source_path: str | None = None,
    build_command: list[str] | None = None,
    output_dir: str | None = None,
    fpr_file: str | None = None,
    json_file: str | None = None,
    csv_file: str | None = None,
    fvdl_file: str | None = None,
    clean_first: bool = True,
    timeout_seconds: int = 1800,
    max_findings: int = 0,
) -> dict[str, Any]:
    project_dir = resolve_project_path(project_path)
    ensure_rules_available()

    resolved_build_id = build_id or default_build_id(project_dir)
    paths = resolve_output_paths(project_dir, output_dir, fpr_file, json_file, csv_file, fvdl_file)
    paths["report_dir"].mkdir(parents=True, exist_ok=True)

    clean_command = build_clean_command(resolved_build_id)
    translate_command = build_translate_command(
        resolved_build_id,
        project_dir,
        source_path,
        build_command,
    )
    scan_command = build_scan_command(resolved_build_id, paths["fpr"])

    clean_process: subprocess.CompletedProcess[str] | None = None
    if clean_first:
        try:
            clean_process = run_command(clean_command, project_dir, timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"Fortify clean timed out after {timeout_seconds}s for {project_dir}"
            ) from exc
        if clean_process.returncode != 0:
            raise RuntimeError({
                "message": "Fortify clean failed.",
                "project_path": str(project_dir),
                "command": clean_command,
                "returncode": clean_process.returncode,
                "stdout_tail": tail_text(clean_process.stdout, 4000),
                "stderr_tail": tail_text(clean_process.stderr, 4000),
            })

    try:
        translate_process = run_command(translate_command, project_dir, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Fortify translation timed out after {timeout_seconds}s for {project_dir}"
        ) from exc
    if translate_process.returncode != 0:
        raise RuntimeError({
            "message": "Fortify translation failed.",
            "project_path": str(project_dir),
            "command": translate_command,
            "returncode": translate_process.returncode,
            "stdout_tail": tail_text(translate_process.stdout, 4000),
            "stderr_tail": tail_text(translate_process.stderr, 4000),
        })

    try:
        scan_process = run_command(scan_command, project_dir, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Fortify scan timed out after {timeout_seconds}s for {project_dir}"
        ) from exc
    if scan_process.returncode != 0:
        raise RuntimeError({
            "message": "Fortify scan failed.",
            "project_path": str(project_dir),
            "command": scan_command,
            "returncode": scan_process.returncode,
            "stdout_tail": tail_text(scan_process.stdout, 4000),
            "stderr_tail": tail_text(scan_process.stderr, 4000),
        })

    if not paths["fpr"].exists():
        raise RuntimeError({
            "message": "Fortify scan finished but did not produce an FPR file.",
            "project_path": str(project_dir),
            "fpr_file": str(paths["fpr"]),
            "scan_command": scan_command,
            "stdout_tail": tail_text(scan_process.stdout, 4000),
            "stderr_tail": tail_text(scan_process.stderr, 4000),
        })

    findings = export_fpr_to_reports(
        paths["fpr"],
        project_dir,
        paths["json"],
        paths["csv"],
        paths["fvdl"],
    )

    if max_findings > 0:
        truncated = len(findings) > max_findings
        returned_findings = findings[:max_findings]
    else:
        truncated = False
        returned_findings = findings

    raw_result = {
        "tool": "fortify",
        "project_path": str(project_dir),
        "build_id": resolved_build_id,
        "raw_report_path": str(paths["fpr"]),
        "fpr_file": str(paths["fpr"]),
        "json_file": str(paths["json"]),
        "csv_file": str(paths["csv"]),
        "fvdl_file": str(paths["fvdl"]),
        "rule_paths": [str(installed_rules_dir())],
        "output_file": str(paths["fpr"]),
        "output_format": "fpr",
        "total_findings": len(findings),
        "returned_findings": len(returned_findings),
        "total_results": len(findings),
        "returned_results": len(returned_findings),
        "truncated": truncated,
        "severity_count": count_by_severity(findings),
        "findings": returned_findings,
        "results": returned_findings,
        "clean_returncode": clean_process.returncode if clean_process else None,
        "translate_returncode": translate_process.returncode,
        "scan_returncode": scan_process.returncode,
        "clean_stdout_tail": tail_text(clean_process.stdout if clean_process else "", 2000),
        "clean_stderr_tail": tail_text(clean_process.stderr if clean_process else "", 2000),
        "translate_stdout_tail": tail_text(translate_process.stdout, 2000),
        "translate_stderr_tail": tail_text(translate_process.stderr, 2000),
        "scan_stdout_tail": tail_text(scan_process.stdout, 2000),
        "scan_stderr_tail": tail_text(scan_process.stderr, 2000),
        "stdout_tail": tail_text(scan_process.stdout, 2000),
        "stderr_tail": tail_text(scan_process.stderr, 2000),
    }
    return normalize_scan_result(raw_result)


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=get_required_env("FORTIFY_MCP_HOST"),
        port=get_env_int("FORTIFY_MCP_PORT"),
        path=get_required_env("FORTIFY_MCP_PATH"),
    )
