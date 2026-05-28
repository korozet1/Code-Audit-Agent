---
name: super-biz-agent-patterns
description: SuperBizAgent 项目架构与代码规范，构建 LLM Agent 应用时的编码参考（LangChain/LangGraph + FastAPI + MCP + RAG）
---

# SuperBizAgent 项目架构与代码规范

此 Skill 提炼自 SuperBizAgent 项目的核心架构模式、编码规范和设计思路。当你需要构建或扩展类似的 LLM Agent 应用（LangChain/LangGraph + FastAPI + MCP + RAG）时，参考此规范。

---

## 一、项目分层架构

采用严格的**四层架构**，每层职责清晰，不可跨层调用：

```
api/          ← HTTP 路由层（薄层）：参数校验、SSE 封装、调用 service
services/     ← 业务服务层：编排 agent 工作流、管理生命周期
agent/        ← Agent 核心层：Plan-Execute-Replan 节点、MCP 客户端
tools/        ← 工具层：@tool 装饰的 LangChain Tool
models/       ← 数据模型层：Pydantic 请求/响应模型
core/         ← 基础设施层：数据库连接、LLM 工厂
```

**规则**：
- api 层只做参数校验和格式转换，**不写业务逻辑**
- services 层负责编排和生命周期，**不直接定义 Tool**
- agent 层实现可复用的节点函数，**不依赖 FastAPI**
- tools 层每个文件一个工具，用 `@tool` 装饰器定义

---

## 二、LangGraph Plan-Execute-Replan 模式

这是 AIOps 智能诊断的核心工作流。三个节点循环执行：

```
Planner → Executor → Replanner ──continue──→ Executor
                         │
                    respond/超限
                         │
                        END
```

### 2.1 状态定义（state.py）

```python
from typing import Annotated, List, TypedDict
import operator

class PlanExecuteState(TypedDict):
    input: str                                        # 用户原始输入
    plan: List[str]                                   # 待执行步骤
    past_steps: Annotated[List[tuple], operator.add]  # 已执行历史（追加，不覆盖）
    response: str                                     # 最终响应
```

**关键**：`Annotated[List[tuple], operator.add]` 实现**追加语义**——每次节点返回 `past_steps` 时，新结果追加到历史列表，而不是覆盖。这是 LangGraph 的 reducer 机制。

### 2.2 规划节点（planner.py）

- 从知识库检索经验文档作为上下文
- 收集本地工具 + MCP 远程工具的描述
- 用 Pydantic `BaseModel` 定义 `Plan` 输出结构（`steps: List[str]`）
- 通过 `llm.with_structured_output(Plan)` 强制 LLM 按结构输出
- 必须 try/except 包裹，失败时返回兜底计划

### 2.3 执行节点（executor.py）

- 取 `plan[0]` 作为当前任务
- 将历史步骤上下文注入 prompt
- 用 `llm.bind_tools(all_tools)` 让 LLM 自主决定调用哪些工具
- 用 `ToolNode` 执行实际工具调用
- 返回 `{"plan": plan[1:], "past_steps": [(task, result)]}`（弹出已执行步骤）
- 失败时同样弹出步骤，但记录失败信息

### 2.4 重规划节点（replanner.py）

三种决策（优先级从高到低）：

| 决策 | 条件 | 行为 |
|------|------|------|
| `respond` | 有 response 字段 或 步骤≥8 或 计划为空 | 生成最终报告 → END |
| `continue` | 计划合理，剩余步骤必要 | 返回 {} → 进入 Executor |
| `replan` | 原计划有严重问题 | 返回新 plan（≤ 原剩余步骤数） |

**安全阀机制**（防止无限循环）：
- 已执行 ≥8 步 → 强制 respond
- 已执行 ≥5 步 → 禁止 replan，强制 respond
- replan 新步骤数 ≤ 当前剩余步骤数

### 2.5 工作流编排（aiops_service.py）

```python
workflow = StateGraph(PlanExecuteState)
workflow.add_node("planner", planner)
workflow.add_node("executor", executor)
workflow.add_node("replanner", replanner)
workflow.set_entry_point("planner")
workflow.add_edge("planner", "executor")
workflow.add_edge("executor", "replanner")
workflow.add_conditional_edges("replanner", should_continue, {...})
compiled = workflow.compile(checkpointer=MemorySaver())
```

- 使用 `MemorySaver` 做会话状态持久化（按 `thread_id` 隔离）
- 用 `graph.astream()` 实现流式输出，每个节点完成时 yield 事件
- 事件格式统一：`{"type": "plan"|"step_complete"|"report"|"complete"|"error", "stage": ..., ...}`

---

## 三、MCP 工具集成规范

### 3.1 MCP 客户端（全局单例 + 重试）

```python
_mcp_client: Optional[MultiServerMCPClient] = None  # 模块级单例

async def get_mcp_client_with_retry(...):
    interceptors = [retry_interceptor]    # 指数退避，最多 3 次
    return await get_mcp_client(servers, interceptors)
```

**规则**：
- MCP 客户端是**全局单例**，所有节点共享
- 重试拦截器使用**指数退避**：`delay * (2 ** attempt)`
- 重试失败后返回 `CallToolResult(isError=True)` 而不是抛异常
- 每个 AIOps 节点独立调用 `get_mcp_client_with_retry()`（内部走单例）

### 3.2 MCP 服务端模式

```python
from fastmcp import FastMCP
mcp = FastMCP("ServiceName")

@mcp.tool()
@log_tool_call          # 自定义装饰器：记录参数和返回值
def my_tool(param: str) -> Dict[str, Any]:
    """工具描述（会暴露给 LLM）。Args/Returns 要写清楚。"""
    ...

if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8003, path="/mcp")
```

**规则**：
- 每个 MCP 服务一个文件
- 工具函数必须写 Google-style docstring（Args/Returns）
- 返回值统一用 `Dict[str, Any]`，方便 LLM 解析
- 用 `streamable-http` 传输协议
- 端口号在 config 中统一管理

---

## 四、Tool 定义规范

### 4.1 本地工具

```python
from langchain_core.tools import tool

@tool
def get_current_time(timezone: str = "Asia/Shanghai") -> str:
    """获取当前时间。
    当用户询问"现在几点"等时间相关问题时使用此工具。
    """
    ...

@tool(response_format="content_and_artifact")
def retrieve_knowledge(query: str) -> Tuple[str, List[Document]]:
    """从知识库中检索相关信息来回答问题。
    当用户问题涉及专业知识、文档内容时使用此工具。
    """
    ...
```

**规则**：
- 每个文件一个工具
- docstring 第一行是简短描述（给 LLM 看），后面可以补充使用场景
- `@tool` 默认返回 `str`；如需同时返回原始对象用 `response_format="content_and_artifact"`
- 工具函数名就是 tool name，用 snake_case

---

## 五、RAG 模式

完整流程：

```
上传文件(.md)
  → DocumentSplitterService
    → MarkdownHeaderTextSplitter（按 #/## 切分）
    → RecursiveCharacterTextSplitter（按长度再切）
    → _merge_small_chunks（合并太小的 chunk，最小 300 字符）
  → DashScopeEmbeddings（text-embedding-v4, 1024 维）
  → Milvus（写入向量库，collection="biz"）

查询时：
  → Embedding 向量化查询
  → Milvus similarity_search（top_k=3）
  → format_docs 格式化（标题层级 + 来源文件 + 内容）
```

**规则**：
- 文档写入前先 `delete_by_source`（用 metadata 中的 `_source` 字段），避免重复
- 每个 chunk 记录 metadata：`_source`（文件路径）、`_file_name`（文件名）、`h1/h2/h3`（标题层级）
- 小 chunk（<300 字符）合并到前一个 chunk，避免碎片化
- chunk_size 和 overlap 在代码中硬编码，不从 config 读取

---

## 六、Pydantic 结构化输出规范

```python
class Plan(BaseModel):
    """计划的输出格式"""
    steps: List[str] = Field(
        description="完成任务所需的不同步骤..."
    )

# 使用：
llm.with_structured_output(Plan)
```

**规则**：
- 每个结构化输出定义一个 Pydantic Model
- `Field(description=...)` 的文本会直接给 LLM 看，要写得具体
- 对于可选字段用 `default_factory=list` 而不是 `= []`（避免可变默认值）
- 解析结果时做 `isinstance` 防御：`if isinstance(result, Plan): ... else: result.get("steps", [])`

---

## 七、Prompt 模板规范

```python
planner_prompt = ChatPromptTemplate.from_messages([
    ("system", dedent("""...""").strip()),
    ("placeholder", "{messages}"),   # 运行时替换
])

# 调用：
chain = planner_prompt | llm.with_structured_output(Plan)
result = await chain.ainvoke({
    "messages": [("user", input_text)],
    "tools_description": tools_description,
    "experience_context": experience_context,
})
```

**规则**：
- 用 `dedent().strip()` 保持代码缩进美观
- `("placeholder", "{messages}")` 用于动态注入消息列表
- system prompt 中明确告诉 LLM 的职责边界（"你只负责计划，不执行工具"）
- 有经验上下文时，用 Markdown 分隔符 `---` 与主 prompt 分隔

---

## 八、配置管理规范

```python
# config.py
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    dashscope_api_key: str = ""
    dashscope_api_base: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    dashscope_model: str = "qwen-max"

    @property
    def mcp_servers(self) -> Dict[str, Dict[str, Any]]:
        return {
            "cls": {"transport": self.mcp_cls_transport, "url": self.mcp_cls_url},
            "monitor": {"transport": self.mcp_monitor_transport, "url": self.mcp_monitor_url},
        }

config = Settings()  # 模块级全局单例
```

**规则**：
- 用 `pydantic-settings` 的 `BaseSettings`
- `extra="ignore"` 防止多余字段报错
- 敏感信息（API Key）默认空字符串，从 `.env` 读取
- 复杂配置（如多个 MCP 服务地址）用 `@property` 聚合
- 全局使用 `from app.config import config` 单例导入

---

## 九、FastAPI 生命周期管理

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时：连接数据库
    milvus_manager.connect()
    yield
    # 关闭时：断开数据库
    milvus_manager.close()

app = FastAPI(lifespan=lifespan)
```

**规则**：
- 数据库连接在 lifespan 中管理，不在模块导入时连接
- 启动日志打印关键信息（监听地址、API 文档地址）
- CORS 全开（`allow_origins=["*"]`），开发阶段方便

---

## 十、SSE 流式输出规范

```python
@router.post("/aiops")
async def diagnose_stream(request: AIOpsRequest):
    async def event_generator():
        async for event in aiops_service.diagnose(session_id=session_id):
            yield {"event": "message", "data": json.dumps(event, ensure_ascii=False)}
            if event.get("type") in ["complete", "error"]:
                break
    return EventSourceResponse(event_generator())
```

**规则**：
- 用 `sse_starlette` 的 `EventSourceResponse`
- 事件格式：`{"event": "message", "data": json_string}`
- `ensure_ascii=False` 保证中文不乱码
- 遇到 `complete` 或 `error` 类型事件时 break 结束流

---

## 十一、错误处理规范（降级运行）

核心原则：**局部失败不影响整体流程**。

```python
# 1. 工具调用失败 → 返回失败信息，不抛异常
try:
    result = await tool.ainvoke(...)
except Exception as e:
    return {"past_steps": [(task, f"执行失败: {str(e)}")]}

# 2. 知识库检索失败 → 空上下文，继续
try:
    docs = await retrieve_knowledge.ainvoke(...)
except Exception as e:
    logger.warning(f"检索失败: {e}")
    docs = ""

# 3. LLM 调用失败 → 兜底计划
try:
    plan = await chain.ainvoke(...)
except Exception:
    return {"plan": ["收集信息", "分析数据", "生成报告"]}

# 4. MCP 连接失败 → 仅本地工具可用
try:
    mcp_tools = await client.get_tools()
except Exception:
    mcp_tools = []
```

---

## 十二、模块组织规范

每个包的 `__init__.py` 做**显式 re-export**：

```python
# app/agent/aiops/__init__.py
from .state import PlanExecuteState
from .planner import planner
from .executor import executor
from .replanner import replanner

__all__ = ["PlanExecuteState", "planner", "executor", "replanner"]
```

**规则**：
- 不鼓励 `from module import *`，用 `__all__` 显式控制
- 外部引用统一用 `from app.agent.aiops import planner` 而不是 `from app.agent.aiops.planner import planner`
- 服务类模块级实例化：`vector_store_manager = VectorStoreManager()`，外部直接 import 使用

---

## 十三、异步模式规范

```python
# 独立运行时入口
if __name__ == "__main__":
    async def main():
        result = await some_async_function()
        print(result)
    asyncio.run(main())

# 流式生成器
async def execute(self, ...) -> AsyncGenerator[Dict[str, Any], None]:
    async for event in self.graph.astream(...):
        yield formatted_event
```

**规则**：
- 所有 LLM 调用用 `ainvoke` / `astream`（异步），不混用同步版本
- `asyncio.run(main())` 只在 `__main__` 中使用
- Service 层的流式方法返回 `AsyncGenerator`

---

## 十四、关键文件扩展指南

**新增 API 路由**：
1. `app/models/` 中定义 Pydantic 请求/响应模型
2. `app/api/` 中新建路由文件
3. `app/main.py` 中 `app.include_router()`

**新增 Tool**：
1. `app/tools/` 中新建文件，用 `@tool` 装饰器
2. 在 `app/tools/__init__.py` 中 re-export
3. 在需要使用此 tool 的 agent 节点中 import

**新增 MCP 服务**：
1. `mcp_servers/` 中新建文件，用 FastMCP
2. `app/config.py` 中添加 url/transport 配置
3. `Settings.mcp_servers` property 中添加对应条目

**新增 AIOps 节点**：
1. `app/agent/aiops/` 中新建文件，签名 `async def xxx(state: PlanExecuteState) -> Dict[str, Any]`
2. `app/agent/aiops/__init__.py` 中 re-export
3. `app/services/aiops_service.py` 中注册节点和边

---

## 十五、禁止事项

- **禁止**在模块导入时连接外部服务（Milvus、MCP 等），必须延迟到运行时
- **禁止**在 api 层写业务逻辑
- **禁止**混用同步/异步 LLM 调用（统一用 async）
- **禁止**硬编码工具参数，MCP 服务地址等应从 config 读取
- **禁止**在 `Field(default=[])` 中使用可变默认值，用 `default_factory=list`
- **禁止**跨层导入（如 api 直接 import agent 内部模块）
