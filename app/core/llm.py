from __future__ import annotations

import asyncio
import json
from typing import Any, Callable
from urllib import error, request

from app.core.config import config


def _is_dashscope_api(api_base: str) -> bool:
    return "dashscope.aliyuncs.com" in api_base.lower()


def _chat_completion_sync(
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int | None,
) -> str:
    api_key = config.resolved_llm_api_key
    api_base = config.resolved_llm_api_base
    model = config.resolved_llm_model

    if not api_key:
        raise RuntimeError("LLM_API_KEY 为空。")
    if not api_base:
        raise RuntimeError("LLM_API_BASE 为空。")
    if not model:
        raise RuntimeError("LLM_MODEL 为空。")

    endpoint = api_base.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(
        endpoint,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=180) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"大模型请求失败：HTTP {exc.code}: {detail}") from exc

    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError(f"大模型响应没有 choices：{body}")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        finish_reason = choices[0].get("finish_reason")
        reasoning = str(message.get("reasoning_content") or "")
        if reasoning:
            raise RuntimeError(
                "大模型响应 content 为空，模型只返回了 "
                f"reasoning_content（{len(reasoning)} 个字符），finish_reason={finish_reason}。"
                "请减少 prompt 大小，在服务商限制内提高单次 max_tokens，"
                "或使用非推理模型。"
            )
        raise RuntimeError(f"大模型响应 content 为空：{body}")
    return str(content)


def _chat_completion_stream_sync(
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int | None,
    progress_callback: Callable[[str], None] | None,
) -> str:
    api_key = config.resolved_llm_api_key
    api_base = config.resolved_llm_api_base
    model = config.resolved_llm_model

    if not api_key:
        raise RuntimeError("LLM_API_KEY 为空。")
    if not api_base:
        raise RuntimeError("LLM_API_BASE 为空。")
    if not model:
        raise RuntimeError("LLM_MODEL 为空。")

    endpoint = api_base.rstrip("/") + "/chat/completions"
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    if _is_dashscope_api(api_base):
        payload["enable_thinking"] = False

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(
        endpoint,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    content_parts: list[str] = []
    reasoning_chars = 0
    usage: dict[str, Any] | None = None
    chunk_count = 0

    try:
        with request.urlopen(req, timeout=600) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line or not line.startswith("data:"):
                    continue

                data_text = line[5:].strip()
                if data_text == "[DONE]":
                    break

                try:
                    body = json.loads(data_text)
                except json.JSONDecodeError:
                    continue

                if body.get("usage"):
                    usage = body.get("usage")

                choices = body.get("choices") or []
                if not choices:
                    continue

                delta = choices[0].get("delta") or {}
                if delta.get("content"):
                    content_parts.append(str(delta["content"]))
                    chunk_count += 1
                    if progress_callback and chunk_count % 100 == 0:
                        progress_callback(
                            f"已流式接收 {sum(len(part) for part in content_parts)} 个字符"
                        )

                if delta.get("reasoning_content"):
                    reasoning_chars += len(str(delta["reasoning_content"]))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"大模型流式请求失败：HTTP {exc.code}: {detail}") from exc

    content = "".join(content_parts)
    if not content:
        raise RuntimeError(
            "大模型流式响应 content 为空。"
            f"reasoning_chars={reasoning_chars}, usage={usage}"
        )

    if progress_callback and usage:
        progress_callback(f"流式调用用量：{usage}")

    return content


async def chat_completion(
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    max_tokens: int | None = None,
) -> str:
    """异步调用 OpenAI-compatible Chat Completions 接口。"""
    return await asyncio.to_thread(_chat_completion_sync, messages, temperature, max_tokens)


async def chat_completion_stream(
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    max_tokens: int | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> str:
    """流式调用 OpenAI-compatible Chat Completions 接口并返回完整内容。"""
    return await asyncio.to_thread(
        _chat_completion_stream_sync,
        messages,
        temperature,
        max_tokens,
        progress_callback,
    )


__all__ = ["chat_completion", "chat_completion_stream"]
