# CCAM Code Audit Agent

Code Audit Agent 是 CCAM 项目里的自动化代码审计编排器。它接收一个项目路径，依次调用 CodeQL MCP 和 Fortify MCP，生成两个标准化扫描结果，随后完成合并、去重候选识别、疑似误报复核候选识别，并输出一份适合人工审计和后续 Agent 修复的 Markdown 报告。

本文档面向两类使用者：

- 审计人员：需要知道怎么跑、产物在哪里、报告里的结论如何理解。
- 开发/维护人员：需要知道代码分层、数据结构、生成逻辑和扩展方式。

## 1. 一分钟跑通

先确保已经激活 Conda 环境，并进入项目根目录：

```powershell
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\project
```

开第一个终端，启动 CodeQL MCP：

```powershell
python mcp_servers\codeql_server.py
```

开第二个终端，启动 Fortify MCP：

```powershell
python mcp_servers\fortify_server.py
```

开第三个终端，运行 Agent：

```powershell
python ccamp\clients\audit_agent_client.py D:\BaiduNetdiskDownload\fortify\java-sec-code-master --language java --queries D:\BaiduNetdiskDownload\codeql\qlpacks\codeql\java-queries\1.11.2\codeql-suites\java-security-and-quality.qls --codeql-timeout-seconds 3600
```

运行完成后查看：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\fortify-codeql-merged-report.md
```

同时会生成：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\codeql-mcp-result.json
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\fortify-mcp-result.json
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\merged-analysis.json
```

## 2. 这个 Agent 做了什么

完整执行链路如下：

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
Executor 合并两个扫描结果
  |
  v
写入 merged-analysis.json
  |
  v
Reporter 生成确定性报告主体
  |
  v
LLM 只生成二次审计意见
  |
  v
写入 fortify-codeql-merged-report.md
```

设计原则：

- 扫描动作由 MCP 服务完成，Agent 不直接拼 CodeQL/Fortify 命令。
- 两个工具的结果先统一成 `ccamp.scan_result.v1` schema。
- 报告里的统计、分布、清单、附录由程序生成，避免大模型漏写或改写数字。
- 大模型只负责解释性内容：去重复核、疑似误报/需确认复核、修复优先级调整。
- 长字段明细使用卡片式 Markdown，不使用超宽表格。

## 3. 环境配置

### 3.1 Python/Conda

项目按当前 Conda 环境运行，不要求使用 `uv`。

最低运行 Agent CLI 需要：

```text
fastmcp
pydantic
pydantic-settings
```

如果需要启动 FastAPI SSE 接口，还需要：

```text
fastapi
sse-starlette
uvicorn
```

`langgraph` 是可选依赖。代码会优先使用 LangGraph；如果环境里没有 `langgraph`，会自动降级为本地顺序执行器。

降级执行器仍然按相同节点语义执行：

```text
planner -> executor -> replanner -> executor -> ... -> complete
```

### 3.2 MCP 端口

默认 MCP 地址：

```env
CODEQL_MCP_URL=http://127.0.0.1:8007/mcp
FORTIFY_MCP_URL=http://127.0.0.1:8008/mcp
```

对应服务端配置：

```env
CODEQL_MCP_HOST=127.0.0.1
CODEQL_MCP_PORT=8007
CODEQL_MCP_PATH=/mcp

FORTIFY_MCP_HOST=127.0.0.1
FORTIFY_MCP_PORT=8008
FORTIFY_MCP_PATH=/mcp
```

Agent 调 MCP 前会自动设置：

```env
NO_PROXY=127.0.0.1,localhost
no_proxy=127.0.0.1,localhost
```

这是为了避免本地 MCP 请求被系统代理转发，导致 `502 Bad Gateway`。

### 3.3 CodeQL

`.env` 里配置 CodeQL 可执行文件：

```env
CODEQL_BIN=D:\BaiduNetdiskDownload\codeql\codeql.exe
```

运行 Agent 时指定 Java 安全质量规则：

```powershell
--language java --queries D:\BaiduNetdiskDownload\codeql\qlpacks\codeql\java-queries\1.11.2\codeql-suites\java-security-and-quality.qls
```

CodeQL 默认输出：

```text
<project>\reports\codeql-result.csv
<project>\reports\codeql-mcp-result.json
```

### 3.4 Fortify

`.env` 里配置 Fortify：

```env
FORTIFY_SOURCEANALYZER_BIN=D:\BaiduNetdiskDownload\fortify\Fortify\bin\sourceanalyzer.exe
FORTIFY_INSTALLED_RULES_DIR=D:\BaiduNetdiskDownload\fortify\Fortify\Core\config\rules
```

Fortify 默认输出：

```text
<project>\reports\fortify.fpr
<project>\reports\audit.fvdl
<project>\reports\fortify.json
<project>\reports\fortify.csv
<project>\reports\fortify-mcp-result.json
```

### 3.5 大模型

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

如果 `LLM_API_KEY` 为空，扫描和合并仍能完成，但报告中的“大模型二次审计意见”会显示生成失败提示。

## 4. 命令行参数

CLI 入口：

```text
ccamp\clients\audit_agent_client.py
```

查看参数：

```powershell
python ccamp\clients\audit_agent_client.py --help
```

常用参数说明：

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
| `--codeql-timeout-seconds` | CodeQL 超时秒数 | `3600` |
| `--fortify-timeout-seconds` | Fortify 超时秒数 | `1800` |
| `--max-codeql-results` | CodeQL MCP 返回 finding 上限，0 为不限 | `0` |
| `--max-fortify-findings` | Fortify MCP 返回 finding 上限，0 为不限 | `0` |
| `--report-output` | Markdown 报告输出路径 | `<project>\reports\fortify-codeql-merged-report.md` |
| `--merged-output` | 合并 JSON 输出路径 | `<project>\reports\merged-analysis.json` |

推荐 Java 项目命令：

```powershell
python ccamp\clients\audit_agent_client.py D:\BaiduNetdiskDownload\fortify\java-sec-code-master --language java --queries D:\BaiduNetdiskDownload\codeql\qlpacks\codeql\java-queries\1.11.2\codeql-suites\java-security-and-quality.qls --codeql-timeout-seconds 3600
```

## 5. 输出文件详解

### 5.1 `codeql-mcp-result.json`

CodeQL MCP 的标准化结果。

关键字段：

```json
{
  "schema_version": "ccamp.scan_result.v1",
  "tool_name": "codeql",
  "status": "success",
  "project_path": "...",
  "raw_report_path": "...\\reports\\codeql-result.csv",
  "total_findings": 186,
  "returned_findings": 186,
  "severity_count": {
    "ERROR": 147,
    "WARNING": 12,
    "RECOMMENDATION": 27
  },
  "findings": []
}
```

`findings` 中每条记录会统一包含：

```text
finding_id
tool_name
rule_id
rule_name
severity
category
message
file
start_line
start_col
end_line
end_col
technology
cwe
owasp
vulnerability_class
tool_specific
```

### 5.2 `fortify-mcp-result.json`

Fortify MCP 的标准化结果。

关键字段：

```json
{
  "schema_version": "ccamp.scan_result.v1",
  "tool_name": "fortify",
  "status": "success",
  "project_path": "...",
  "raw_report_path": "...\\reports\\fortify.fpr",
  "total_findings": 45,
  "returned_findings": 45,
  "severity_count": {
    "MEDIUM": 30,
    "CRITICAL": 15
  },
  "findings": []
}
```

Fortify 服务会把 FPR 中的 `audit.fvdl` 解出，再解析为 JSON/CSV。

### 5.3 `merged-analysis.json`

这是 Agent 的核心中间产物。报告不是直接从两个原始 JSON 自由生成，而是先生成这个结构化合并结果。

关键字段：

```json
{
  "project_path": "...",
  "tool_summaries": {
    "codeql": {},
    "fortify": {}
  },
  "summary": {
    "raw_total_findings": 231,
    "merged_groups": 80,
    "vulnerability_types": 17,
    "direct_overlap_groups": 6,
    "type_overlap_count": 5,
    "high_priority_groups": 50,
    "deduplication_candidates": 39,
    "false_positive_review_candidates": 26,
    "files_involved": 53
  },
  "type_distribution": [],
  "direct_overlap_groups": [],
  "high_priority_groups": [],
  "deduplication_candidates": [],
  "false_positive_review_candidates": [],
  "groups": []
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `summary` | 总览统计 |
| `type_distribution` | 按漏洞类型统计两个工具的覆盖情况 |
| `direct_overlap_groups` | 同类型、同文件、双工具同时发现的问题组 |
| `high_priority_groups` | P0/P1 优先复核清单 |
| `deduplication_candidates` | 去重候选 |
| `false_positive_review_candidates` | 疑似误报或需人工确认候选 |
| `groups` | 所有合并后的问题组 |

### 5.4 `fortify-codeql-merged-report.md`

最终 Markdown 报告。

报告结构：

```text
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
```

报告生成策略：

- 统计表、类型分布、清单和附录由程序生成。
- 大模型只生成“二次审计意见”。
- 长字段内容使用卡片式条目，避免 Markdown 宽表挤压。
- 附录完整列出所有合并问题组，不让模型省略。

## 6. 合并规则

### 6.1 为什么不按 rule_id 合并

CodeQL 和 Fortify 的规则体系不同。相同漏洞在两个工具里的规则名、行号和描述可能都不一样。

例如同一个 SQL 注入问题可能表现为：

```text
CodeQL: Query built from user-controlled sources
Fortify: SQL Injection
```

因此默认合并键是：

```text
漏洞类型归一化 + 文件路径
```

### 6.2 漏洞类型归一化

归一化逻辑位于：

```text
app\agent\code_audit\merge.py
```

会根据规则名、描述、消息、文件路径等文本，把 finding 归到统一类型。

当前支持的典型类型：

```text
SQL 注入
XXE/XML 实体注入
SSRF
XSS
反序列化
路径遍历/文件路径控制
命令执行/命令注入
HTTP 响应拆分/CRLF
日志注入
Cookie 安全配置
表达式/模板注入
文件上传风险
Spring Boot Actuator 暴露
资源泄露
信息泄露
敏感信息/密码管理
```

### 6.3 优先级口径

优先级由程序计算。

| 优先级 | 含义 |
| --- | --- |
| `P0-双工具确认` | 同一问题组被 CodeQL 和 Fortify 同时发现 |
| `P0-高危类型` | 高危漏洞类型且严重级别较高 |
| `P1-高风险` | 其他高严重级别问题 |
| `P2-中风险` | 中风险或需要上下文确认的问题 |
| `P3-低风险/质量` | 低风险、质量建议或最佳实践问题 |

高危类型包括：

```text
SQL 注入
命令执行/命令注入
反序列化
SSRF
XXE/XML 实体注入
路径遍历/文件路径控制
XSS
文件上传风险
```

## 7. 去重与误报复核

### 7.1 去重候选

程序会先生成 `deduplication_candidates`。

候选条件包括：

- 同一漏洞类型和同一文件出现多条 finding。
- 同一问题被两个工具同时发现。
- 同一工具在同一文件上命中多个相近规则。

报告中的去重候选使用卡片式条目：

```markdown
#### D-003 SSRF | SSRF.java

- **文件**：src/main/java/org/joychou/controller/SSRF.java
- **来源**：codeql, fortify
- **原始条数**：23
- **行号**：36, 110
- **规则**：Server-side request forgery, System Information Leak
- **程序建议**：review_as_one_issue_group
- **理由**：同一漏洞类型和同一文件被多个工具同时发现，可能是同一根因的跨工具重复。
```

### 7.2 疑似误报与需人工确认候选

程序会生成 `false_positive_review_candidates`。

候选条件包括：

- 单工具命中，没有双工具确认。
- 缺少明确行号。
- 类型强依赖运行上下文，例如日志注入、资源泄露、Cookie 安全配置。
- P3 低风险或代码质量建议。

报告中的复核候选使用卡片式条目：

```markdown
#### F-003 P1-高风险 | 日志注入 | FileUpload.java

- **文件**：src/main/java/org/joychou/controller/FileUpload.java
- **来源**：codeql
- **行号**：106, 124, 152, 153, 161, 165
- **规则**：Log Injection
- **程序建议**：needs_manual_or_llm_source_review
- **理由**：该类型常需要结合运行上下文确认，单工具命中时建议复核可达性和真实攻击面。
```

### 7.3 大模型参与方式

大模型不会再生成整篇报告。

它只生成：

```text
去重复核意见
疑似误报/需确认复核意见
修复优先级调整建议
```

给模型的输入包括：

- `summary`
- `direct_overlap_groups`
- `deduplication_candidates`
- `false_positive_review_candidates`
- 候选 finding 对应的源码片段

如果源码片段为空，模型必须说明证据不足，不能把问题写成确定误报。

这样可以避免两个问题：

- 上下文太长导致模型漏读或压缩输出。
- 模型自由生成统计表时改写数字、合并类别或省略附录。

## 8. 报告可读性策略

早期版本把所有明细都放进 Markdown 表格。长路径、多行号、多规则会把列挤碎，阅读体验很差。

当前策略：

- 短字段统计保留表格。
- 长字段明细全部使用卡片式条目。
- 每条问题有稳定编号。
- 字段竖排展示，适合窄屏、IDE Markdown 预览和复制到工单系统。

编号含义：

| 前缀 | 含义 |
| --- | --- |
| `O-xxx` | 直接重合问题组 |
| `D-xxx` | 去重候选 |
| `F-xxx` | 疑似误报或需人工确认候选 |
| `P-xxx` | P0/P1 优先复核项 |
| `A-xxx` | 附录完整明细 |

## 9. API 使用

API 路由：

```text
POST /code-audit/stream
```

实现文件：

```text
app\api\code_audit.py
```

API 返回 SSE 事件，事件格式统一为：

```json
{
  "type": "step_complete",
  "stage": "executor",
  "message": "...",
  "data": {}
}
```

典型事件：

| type | 说明 |
| --- | --- |
| `start` | 工作流开始 |
| `plan` | 已生成执行计划 |
| `step_complete` | 某个步骤执行完成 |
| `replan` | 工作流继续/结束决策 |
| `complete` | 完成 |
| `complete_with_errors` | 完成但有错误 |

API 层只做参数校验和 SSE 封装，业务逻辑在 service 层。

## 10. 代码结构

```text
app/
  api/
    code_audit.py
      SSE API 路由

  models/
    code_audit.py
      CodeAuditRequest
      CodeAuditEvent

  services/
    code_audit_service.py
      业务编排服务

  agent/
    code_audit/
      planner.py
        生成计划

      executor.py
        执行扫描、合并、报告生成

      replanner.py
        控制继续或结束

      scanner.py
        调用 CodeQL MCP 和 Fortify MCP

      merge.py
        合并、归一化、优先级、去重候选、误报候选

      reporter.py
        确定性报告生成 + 大模型二次审计意见

      workflow.py
        LangGraph 工作流或本地降级执行器

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
      Agent CLI 入口

    codeql_client.py
      CodeQL MCP 单独测试客户端

    fortify_client.py
      Fortify MCP 单独测试客户端

  shared/
    mcp_client.py
      FastMCP 调用和结果解包

    report_schema.py
      扫描结果标准化 schema
```

## 11. 故障排查

### 11.1 `ModuleNotFoundError: No module named 'ccamp'`

原因通常是没有从项目根目录运行脚本。

推荐：

```powershell
cd /d D:\BaiduNetdiskDownload\CCAM\project
python ccamp\clients\audit_agent_client.py ...
```

当前 client 已经做了直接脚本运行兼容，会自动把项目根目录加入 `sys.path`。

### 11.2 MCP 连接返回 `502 Bad Gateway`

常见原因是本地请求走了代理。

当前 Agent 已在 `ccamp/shared/mcp_client.py` 中设置：

```env
NO_PROXY=127.0.0.1,localhost
no_proxy=127.0.0.1,localhost
```

仍然失败时检查：

- `python mcp_servers\codeql_server.py` 是否还在运行。
- `python mcp_servers\fortify_server.py` 是否还在运行。
- `.env` 里的 MCP URL 是否和端口一致。
- 系统代理是否强制拦截本地 HTTP。

### 11.3 `LLM_API_KEY is empty`

说明没有配置大模型 key。

配置：

```env
LLM_API_KEY=你的key
LLM_API_BASE=https://你的服务商地址/v1
LLM_MODEL=你的模型名
```

扫描和合并不依赖 LLM。LLM 失败时，主要影响报告中的二次审计意见。

### 11.4 报告数字和 JSON 是否一致

当前报告的关键统计由程序从 `merged-analysis.json` 渲染，不由模型自由生成。

重点字段：

```text
raw_total_findings
merged_groups
vulnerability_types
direct_overlap_groups
high_priority_groups
deduplication_candidates
false_positive_review_candidates
```

如果要核对，优先查看：

```text
<project>\reports\merged-analysis.json
```

### 11.5 报告是否会因为上下文太长漏掉 JSON

当前版本不会把完整 JSON 交给模型写整篇报告。

程序负责完整输出：

- 扫描概览
- 类型分布
- 直接重合问题组
- 去重候选
- 疑似误报/需确认候选
- P0/P1 清单
- 附录完整明细

模型只处理二次审计意见，因此上下文压力较小，且不会导致附录丢失。

### 11.6 Markdown 表格太宽

当前版本已经避免在长字段明细里使用宽表。

只有短统计表使用表格。长路径、多行号、多规则统一使用卡片式条目。

## 12. 修改和扩展

### 12.1 新增漏洞类型归一化

修改：

```text
app\agent\code_audit\merge.py
```

更新 `TYPE_PATTERNS`。

示例：

```python
(("jwt", "json web token"), "JWT 安全配置")
```

### 12.2 调整优先级

修改：

```text
app\agent\code_audit\merge.py
```

主要函数：

```text
priority_for_group
```

如果某类漏洞需要进入 P0，可加入：

```text
HIGH_RISK_TYPES
```

### 12.3 调整误报候选规则

修改：

```text
FALSE_POSITIVE_HINT_TYPES
false_positive_reason
```

例如可以把某些质量类 CodeQL 规则默认放入误报复核队列。

### 12.4 调整报告样式

修改：

```text
app\agent\code_audit\reporter.py
```

关键函数：

```text
render_deterministic_report
render_issue_cards
table
```

如果要改回表格，只改局部渲染即可，不影响扫描和合并逻辑。

### 12.5 接入新的扫描工具

建议步骤：

1. 在 `mcp_servers/` 新增 MCP 服务入口。
2. 在 `ccamp/<tool>/server.py` 实现扫描工具。
3. 在 `ccamp/shared/report_schema.py` 补充标准化字段。
4. 在 `app/agent/code_audit/scanner.py` 增加调用逻辑。
5. 在 `app/agent/code_audit/merge.py` 合并来源统计里加入新工具。

## 13. 推荐审计流程

一次完整审计建议按以下顺序执行：

1. 跑 Agent，生成四个产物。
2. 先看 `fortify-codeql-merged-report.md` 的结论和 P0/P1 清单。
3. 对 `O-xxx` 双工具确认问题优先复核。
4. 对 `D-xxx` 去重候选决定工单粒度。
5. 对 `F-xxx` 疑似误报/需确认项看源码后确认是否降级。
6. 根据 `A-xxx` 附录完整明细补齐遗漏问题。
7. 修复 P0/P1。
8. 重新运行 CodeQL 和 Fortify。
9. 对比新旧 `merged-analysis.json`，确认高危问题是否消除。

## 14. 后续可做

可选增强方向：

- 输出 DOCX/PDF 审计报告。
- 把 `P-xxx` 自动转成 Jira/GitHub Issue。
- 对 `F-xxx` 人工确认结果生成 suppression 配置。
- 对 P0/P1 自动生成修复 Patch。
- 修复后自动二次扫描并生成差异报告。
- 将确认过的误报和修复模式沉淀为 Agent 经验库。
