from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.code_audit import router as code_audit_router
from app.core.config import config


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时
    print(f"CCAM Agent starting on http://{config.app_host}:{config.app_port}")
    print(f"API docs: http://{config.app_host}:{config.app_port}/docs")
    print(f"MCP servers configured: {list(config.mcp_servers.keys())}")
    yield
    # 关闭时
    print("CCAM Agent shutting down.")


app = FastAPI(
    title="CCAM — Code Audit Agent",
    description="LLM Agent orchestration for CodeQL and Fortify static analysis",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(code_audit_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=config.app_host,
        port=config.app_port,
        reload=True,
    )
