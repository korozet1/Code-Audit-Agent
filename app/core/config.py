from __future__ import annotations

from typing import Any, Dict

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LLM ---
    llm_api_key: str = Field(
        default="",
        description="OpenAI-compatible API key. Preferred over provider-specific keys.",
    )
    llm_api_base: str = Field(
        default="",
        description="OpenAI-compatible API base URL, for example https://api.example.com/v1.",
    )
    llm_model: str = Field(
        default="",
        description="Chat model name used for report generation.",
    )
    dashscope_api_key: str = ""
    dashscope_api_base: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    dashscope_model: str = "qwen-max"

    # --- MCP: CodeQL ---
    codeql_mcp_host: str = "127.0.0.1"
    codeql_mcp_port: int = 8007
    codeql_mcp_path: str = "/mcp"
    codeql_mcp_url: str = Field(
        default="http://127.0.0.1:8007/mcp",
        description="Full streamable HTTP URL for CodeQL MCP client.",
    )

    # --- MCP: Fortify ---
    fortify_mcp_host: str = "127.0.0.1"
    fortify_mcp_port: int = 8008
    fortify_mcp_path: str = "/mcp"
    fortify_mcp_url: str = Field(
        default="http://127.0.0.1:8008/mcp",
        description="Full streamable HTTP URL for Fortify MCP client.",
    )

    # --- Server ---
    app_host: str = "127.0.0.1"
    app_port: int = 8000

    @property
    def resolved_llm_api_key(self) -> str:
        return self.llm_api_key or self.dashscope_api_key

    @property
    def resolved_llm_api_base(self) -> str:
        return self.llm_api_base or self.dashscope_api_base

    @property
    def resolved_llm_model(self) -> str:
        return self.llm_model or self.dashscope_model

    @property
    def mcp_servers(self) -> Dict[str, Dict[str, Any]]:
        return {
            "codeql": {
                "transport": "streamable-http",
                "url": self.codeql_mcp_url,
            },
            "fortify": {
                "transport": "streamable-http",
                "url": self.fortify_mcp_url,
            },
        }


config = Settings()
