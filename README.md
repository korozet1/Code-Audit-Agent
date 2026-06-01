# CCAM Code Audit Agent

CCAM Code Audit Agent 是一个面向代码安全审计的自动化编排工具。它接收一个待审计项目路径，调用 CodeQL MCP 和 Fortify MCP 完成静态扫描，再以 Fortify 为主线合并扫描结果，最终生成 Markdown 审计报告。

当前项目支持两类报告：

- 二方合并报告：Fortify + CodeQL，以 Fortify 作为最终问题全集，CodeQL 只作为佐证。
- 三方对比报告：Fortify + CodeQL + AI 直接审代码结果，仍以 Fortify 作为最终问题全集，CodeQL 和 AI 结果只作为对比、误报复核和优先级调整证据。

## 1. 推荐使用流程

完整审计建议按下面顺序执行。

### 1.1 启动 MCP 服务

先激活 Conda 环境并进入项目目录：

```powershell
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\project
```

打开第一个终端，启动 CodeQL MCP：

```powershell
python mcp_servers\codeql_server.py
```

打开第二个终端，启动 Fortify MCP：

```powershell
python mcp_servers\fortify_server.py
```

### 1.2 生成 Fortify + CodeQL 二方合并结果

在第三个终端运行 Agent：

```powershell
python ccamp\clients\audit_agent_client.py D:\BaiduNetdiskDownload\fortify\java-sec-code-master --language java --queries D:\BaiduNetdiskDownload\codeql\qlpacks\codeql\java-queries\1.11.2\codeql-suites\java-security-and-quality.qls --codeql-timeout-seconds 3600
```

执行完成后会生成：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\codeql-mcp-result.json
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\fortify-mcp-result.json
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\merged-analysis.json
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\fortify-codeql-merged-report.md
```

### 1.3 补充 AI 直接审代码结果

如果需要生成三方报告，先准备 AI 直接审代码结果 Markdown，例如：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\deepseekv4pro.md
```

该文件一般来自你直接让大模型审查源码后得到的结果。

### 1.4 生成 Fortify + CodeQL + AI 三方报告

运行三方报告客户端：

```powershell
python ccamp\clients\three_way_report_client.py D:\BaiduNetdiskDownload\fortify\java-sec-code-master --merged-input D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\merged-analysis.json --ai-review-input D:\BaiduNetdiskDownload\fortify\java-sec-code-master\deepseekv4pro.md
```

执行完成后会生成：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\fortify-codeql-ai-final-report.md
```

三方报告仍然以 Fortify 作为最终问题全集。CodeQL 和 AI 直接审代码结果只作为对比佐证，用于重合分析、疑似误报复核和优先级调整。

## 2. 环境安装

### 2.1 Python 和 Conda

本项目按 Conda 环境运行和调试，不要求使用 `uv`。

推荐安装方式：

```powershell
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\project
python -m pip install -e .
```

如果只想在当前 Conda 环境中补齐依赖，也可以使用：

```powershell
python -m pip install fastapi "uvicorn[standard]" sse-starlette pydantic pydantic-settings langchain langgraph langchain-community fastmcp
```

### 2.2 不要使用 uv

不要在本项目目录中执行下面这些命令：

```powershell
uv sync
uv run ...
uv pip install ...
```

项目根目录存在 `pyproject.toml`。`uv` 检测到它之后会自动生成 `.venv/` 和 `uv.lock`。当前项目使用 Conda 环境，这两个文件不需要提交。

如果已经生成，可以删除：

```powershell
Remove-Item -Recurse -Force .venv
Remove-Item -Force uv.lock
```

### 2.3 提交前不应包含的文件

通常不应提交：

```text
.venv/
uv.lock
__pycache__/
*.pyc
.idea/
```

注意：`.env` 可能包含本地路径和 API Key。如果 `.env` 已经被 Git 跟踪，即使 `.gitignore` 里写了 `.env`，它仍然可能被提交。提交前必须确认其中没有真实密钥。

## 3. 配置说明

项目使用 `.env` 读取配置。核心配置项如下。

### 3.1 MCP 地址

默认 MCP 地址：

```env
CODEQL_MCP_URL=http://127.0.0.1:8007/mcp
FORTIFY_MCP_URL=http://127.0.0.1:8008/mcp
```

对应服务端端口：

```env
CODEQL_MCP_HOST=127.0.0.1
CODEQL_MCP_PORT=8007
CODEQL_MCP_PATH=/mcp

FORTIFY_MCP_HOST=127.0.0.1
FORTIFY_MCP_PORT=8008
FORTIFY_MCP_PATH=/mcp
```

Agent 调用本地 MCP 前会设置：

```env
NO_PROXY=127.0.0.1,localhost
no_proxy=127.0.0.1,localhost
```

这是为了避免本地 MCP 请求被系统代理转发，导致 `502 Bad Gateway`。

### 3.2 CodeQL

配置 CodeQL 可执行文件：

```env
CODEQL_BIN=D:\BaiduNetdiskDownload\codeql\codeql.exe
```

Java 安全规则示例：

```powershell
--language java --queries D:\BaiduNetdiskDownload\codeql\qlpacks\codeql\java-queries\1.11.2\codeql-suites\java-security-and-quality.qls
```

默认输出：

```text
<project>\reports\codeql-result.csv
<project>\reports\codeql-mcp-result.json
```

### 3.3 Fortify

配置 Fortify：

```env
FORTIFY_SOURCEANALYZER_BIN=D:\BaiduNetdiskDownload\fortify\Fortify\bin\sourceanalyzer.exe
FORTIFY_INSTALLED_RULES_DIR=D:\BaiduNetdiskDownload\fortify\Fortify\Core\config\rules
```

默认输出：

```text
<project>\reports\fortify.fpr
<project>\reports\audit.fvdl
<project>\reports\fortify.json
<project>\reports\fortify.csv
<project>\reports\fortify-mcp-result.json
```

### 3.4 大模型

大模型使用 OpenAI-compatible `/chat/completions` 接口。

推荐使用通用配置：

```env
LLM_API_KEY=你的key
LLM_API_BASE=https://你的服务商地址/v1
LLM_MODEL=你的模型名
```

如果没有设置 `LLM_*`，代码会回退到旧的 DashScope 配置：

```env
DASHSCOPE_API_KEY=
DASHSCOPE_API_BASE=https://dashscope.aliyuncs.com/compatible-mode/v1
DASHSCOPE_MODEL=qwen-max
```

三方报告客户端使用流式 Chat Completions。对于 DashScope/百炼这类长输出容易非流式断连的场景，流式调用可以降低长响应中断概率。

## 4. 核心合并口径

### 4.1 Fortify 是最终问题全集

当前合并规则是：

```text
最终问题全集 = Fortify 主问题组
CodeQL = 佐证工具
AI 直接审代码结果 = 第三方佐证
CodeQL 独有问题 = 默认忽略，不进入最终问题清单
AI 独有问题 = 只进入观察项，不进入最终问题清单
```

### 4.2 CodeQL 匹配规则

CodeQL finding 只有满足下面条件时，才会挂到 Fortify 主问题组上：

```text
同文件 + 同归一化漏洞类型
```

原因是 CodeQL 和 Fortify 的规则体系不同。同一个安全问题在两个工具中可能有不同规则名、描述和行号。例如：

```text
CodeQL: Query built from user-controlled sources
Fortify: SQL Injection
```

因此项目不按 `rule_id` 直接合并，而是先做漏洞类型归一化，再按文件匹配。

### 4.3 AI 直接审代码结果的作用

AI 审查结果只做辅助判断：

- 支持 Fortify 主问题时，用作证据增强。
- 与 Fortify 问题语义接近但位置不完全一致时，标记为需人工确认。
- AI 独有发现只写入“非 Fortify 主线观察项”，不进入最终问题列表。

## 5. Agent 执行流程

二方合并流程：

```text
用户输入项目路径
  |
  v
Planner 生成固定执行计划
  |
  v
Executor 调用 CodeQL MCP
  |
  v
写入 codeql-mcp-result.json
  |
  v
Executor 调用 Fortify MCP
  |
  v
写入 fortify-mcp-result.json
  |
  v
Executor 以 Fortify 为主线合并两个扫描结果
  |
  v
写入 merged-analysis.json
  |
  v
Reporter 生成 fortify-codeql-merged-report.md
```

三方报告流程：

```text
读取 merged-analysis.json
  |
  v
读取 AI 直接审代码 Markdown
  |
  v
以 Fortify 主问题组为最终问题全集
  |
  v
把 CodeQL 和 AI 结果作为佐证进行三方对比
  |
  v
生成 fortify-codeql-ai-final-report.md
```

## 6. 命令行入口

### 6.1 二方合并 Agent

入口：

```text
ccamp\clients\audit_agent_client.py
```

查看参数：

```powershell
python ccamp\clients\audit_agent_client.py --help
```

常用参数：

| 参数 | 作用 | 默认值 |
| --- | --- | --- |
| `project_path` | 待扫描项目路径 | 必填 |
| `--language` | CodeQL 语言 | `auto` |
| `--queries` | CodeQL query suite 或 qlpack 路径 | 空 |
| `--database-path` | CodeQL database 目录 | 空 |
| `--codeql-output` | CodeQL 原始结果输出文件 | 空 |
| `--codeql-output-format` | CodeQL 输出格式 | 空 |
| `--source-root` | CodeQL source-root | `.` |
| `--build-mode` | CodeQL build-mode | `none` |
| `--codeql-timeout-seconds` | CodeQL 超时时间 | `3600` |
| `--fortify-timeout-seconds` | Fortify 超时时间 | `1800` |
| `--max-codeql-results` | CodeQL MCP 返回 finding 上限，`0` 表示不限制 | `0` |
| `--max-fortify-findings` | Fortify MCP 返回 finding 上限，`0` 表示不限制 | `0` |
| `--report-output` | Markdown 报告输出路径 | `<project>\reports\fortify-codeql-merged-report.md` |
| `--merged-output` | 合并 JSON 输出路径 | `<project>\reports\merged-analysis.json` |

### 6.2 三方报告客户端

入口：

```text
ccamp\clients\three_way_report_client.py
```

查看参数：

```powershell
python ccamp\clients\three_way_report_client.py --help
```

常用参数：

| 参数 | 作用 | 默认值 |
| --- | --- | --- |
| `project_path` | 待审计项目路径 | 必填 |
| `--merged-input` | `merged-analysis.json` 路径 | `<project>\reports\merged-analysis.json` |
| `--ai-review-input` | AI 直接审代码 Markdown 路径 | `<project>\ai-code-review-result.md` |
| `--report-output` | 三方 Markdown 报告输出路径 | `<project>\reports\fortify-codeql-ai-final-report.md` |
| `--temperature` | 大模型温度 | `0.1` |
| `--max-tokens` | 最大输出 token 数，不填则使用服务商默认值 | 空 |
| `--max-merged-chars` | merged JSON 字符数上限，`0` 表示完整输入 | `0` |
| `--max-ai-review-chars` | AI 审查 Markdown 字符数上限，`0` 表示完整输入 | `0` |

## 7. 输出文件说明

### 7.1 `codeql-mcp-result.json`

CodeQL MCP 的标准化结果。核心字段：

```json
{
  "schema_version": "ccamp.scan_result.v1",
  "tool_name": "codeql",
  "status": "success",
  "project_path": "...",
  "raw_report_path": "...\\reports\\codeql-result.csv",
  "total_findings": 186,
  "returned_findings": 186,
  "severity_count": {},
  "findings": []
}
```

### 7.2 `fortify-mcp-result.json`

Fortify MCP 的标准化结果。核心字段：

```json
{
  "schema_version": "ccamp.scan_result.v1",
  "tool_name": "fortify",
  "status": "success",
  "project_path": "...",
  "raw_report_path": "...\\reports\\fortify.fpr",
  "total_findings": 45,
  "returned_findings": 45,
  "severity_count": {},
  "findings": []
}
```

### 7.3 `merged-analysis.json`

二方合并后的结构化中间结果，也是三方报告的主要输入。

关键字段：

| 字段 | 说明 |
| --- | --- |
| `summary` | 总览统计 |
| `tool_summaries` | CodeQL/Fortify 两个工具的执行概览 |
| `ignored_codeql_summary` | CodeQL 独有项忽略统计 |
| `type_distribution` | Fortify 主问题组的漏洞类型分布 |
| `direct_overlap_groups` | 匹配到 CodeQL 佐证的 Fortify 主问题组 |
| `high_priority_groups` | P0/P1 优先复核清单 |
| `deduplication_candidates` | 去重候选 |
| `false_positive_review_candidates` | 疑似误报或需人工确认候选 |
| `groups` | 所有 Fortify 主问题组 |

### 7.4 `fortify-codeql-merged-report.md`

Fortify + CodeQL 二方合并报告，主要用于查看：

- 扫描概览。
- 合并规则和风险口径。
- 漏洞类型分布。
- CodeQL 与 Fortify 的重合和差异。
- 去重候选。
- 疑似误报和需人工确认项。
- P0/P1 优先复核清单。
- 按漏洞类型的修复建议。
- 附录中的合并明细。

### 7.5 `fortify-codeql-ai-final-report.md`

Fortify + CodeQL + AI 三方对比报告，主要用于查看：

- Fortify 主问题组是否被 CodeQL 或 AI 支持。
- 单个问题中 Fortify、CodeQL、AI 三方证据对比。
- AI 审查结果对误报复核和优先级调整的帮助。
- AI 独有观察项是否需要后续人工单独评估。

## 8. 报告可读性要求

三方报告提示词强制使用固定 Markdown 版式：

- 全文只允许一个一级标题。
- 主章节使用二级标题。
- 单个漏洞条目和附录条目使用三级标题。
- Fortify / CodeQL / AI 三方对比使用固定表格列：来源、命中状态、证据摘要、位置、结论。
- 禁止使用“同上”“略”“参见前文”等省略写法。
- 长路径、长规则、长解释不塞进宽表格，放在“分析结论”和“处理建议”中。
- 附录 A 必须完整列出所有 Fortify 主问题组。

## 9. 代码结构

```text
app/
  api/
    code_audit.py
      SSE API 路由

  models/
    code_audit.py
      CodeAuditRequest、CodeAuditEvent

  services/
    code_audit_service.py
      业务编排服务

  agent/
    code_audit/
      planner.py
        生成执行计划
      executor.py
        执行扫描、合并和报告生成
      replanner.py
        控制继续或结束
      scanner.py
        调用 CodeQL MCP 和 Fortify MCP
      merge.py
        合并、归一化、优先级、去重候选、误报候选
      reporter.py
        二方报告生成
      workflow.py
        LangGraph 工作流或本地降级执行器

    code_audit_three_way_report/
      generator.py
        三方报告生成
      __main__.py
        三方报告模块入口

  core/
    config.py
      配置管理
    llm.py
      OpenAI-compatible Chat Completions 调用

ccamp/
  codeql/server.py
    CodeQL MCP 服务

  fortify/server.py
    Fortify MCP 服务

  clients/
    audit_agent_client.py
      二方合并 Agent CLI
    codeql_client.py
      CodeQL MCP 单独测试客户端
    fortify_client.py
      Fortify MCP 单独测试客户端
    three_way_report_client.py
      三方报告 CLI

  shared/
    mcp_client.py
      MCP 调用和结果解包
    report_schema.py
      扫描结果标准化 schema
```

## 10. API 使用

API 路由：

```text
POST /code-audit/stream
```

实现文件：

```text
app\api\code_audit.py
```

API 返回 SSE 事件，事件结构示例：

```json
{
  "type": "step_complete",
  "stage": "executor",
  "message": "...",
  "data": {}
}
```

常见事件：

| type | 说明 |
| --- | --- |
| `start` | 工作流开始 |
| `plan` | 已生成执行计划 |
| `step_complete` | 某个步骤执行完成 |
| `replan` | 工作流继续或结束决策 |
| `complete` | 完成 |
| `complete_with_errors` | 完成但有错误 |

## 11. 常见问题

### 11.1 `ModuleNotFoundError: No module named 'ccamp'`

通常是没有从项目根目录运行脚本。

推荐：

```powershell
cd /d D:\BaiduNetdiskDownload\CCAM\project
python ccamp\clients\audit_agent_client.py ...
```

当前 client 已经做了直接脚本运行兼容，会自动把项目根目录加入 `sys.path`。

### 11.2 MCP 返回 `502 Bad Gateway`

常见原因：

- CodeQL MCP 或 Fortify MCP 没有启动。
- `.env` 中 MCP URL 和实际端口不一致。
- 本地 HTTP 请求被系统代理拦截。

检查：

```powershell
python mcp_servers\codeql_server.py
python mcp_servers\fortify_server.py
```

并确认：

```env
CODEQL_MCP_URL=http://127.0.0.1:8007/mcp
FORTIFY_MCP_URL=http://127.0.0.1:8008/mcp
```

### 11.3 大模型 key 为空

如果看到 `LLM_API_KEY 为空`，说明没有配置大模型 key。

配置：

```env
LLM_API_KEY=你的key
LLM_API_BASE=https://你的服务商地址/v1
LLM_MODEL=你的模型名
```

扫描和合并不依赖 LLM。LLM 失败主要影响报告中的解释性内容。

### 11.4 DashScope/百炼长输出中断

三方报告客户端已经使用流式输出。如果仍然失败，优先检查：

- 账号是否欠费或无权限。
- 模型名是否在百炼可用。
- API Key 是否属于百炼，不要把 DeepSeek 官方 key 用到百炼地址。
- 服务商是否限制单次上下文或输出长度。

### 11.5 Markdown 报告表格太宽

三方报告已经在提示词中限制版式：

- 总览只用短表格。
- 单个问题使用三方对比小表。
- 长内容放到表格后的分析段落。

如果仍然可读性差，优先调整：

```text
app\agent\code_audit_three_way_report\generator.py
```

## 12. 修改和扩展

### 12.1 调整合并规则

修改：

```text
app\agent\code_audit\merge.py
```

重点函数和配置：

```text
TYPE_PATTERNS
HIGH_RISK_TYPES
priority_for_group
false_positive_reason
```

### 12.2 调整二方报告

修改：

```text
app\agent\code_audit\reporter.py
```

### 12.3 调整三方报告提示词

修改：

```text
app\agent\code_audit_three_way_report\generator.py
```

重点函数：

```text
build_system_prompt
build_user_prompt
```

### 12.4 接入新的扫描工具

建议步骤：

1. 在 `mcp_servers/` 新增 MCP 服务入口。
2. 在 `ccamp/<tool>/server.py` 实现扫描工具。
3. 在 `ccamp/shared/report_schema.py` 补充标准化字段。
4. 在 `app/agent/code_audit/scanner.py` 增加调用逻辑。
5. 在 `app/agent/code_audit/merge.py` 中定义该工具是主工具、佐证工具还是观察工具。

当前系统以 Fortify 为主工具。接入新工具前，需要先确定它是否参与最终问题全集。

## 13. 提交前检查清单

提交前建议执行：

```powershell
git status --short
```

重点检查：

- `.env` 是否包含真实 key。
- `.venv/` 是否被误加入。
- `uv.lock` 是否被误加入。
- `__pycache__/` 和 `*.pyc` 是否被误加入。
- `.idea/` 是否需要提交。
- 测试脚本是否只是临时验证文件。

可以检查 Python 语法：

```powershell
python -m py_compile app/core/llm.py app/agent/code_audit_three_way_report/generator.py ccamp/clients/three_way_report_client.py
```

如果执行 `py_compile` 后出现 `__pycache__` 变更，不要提交这些编译产物。
