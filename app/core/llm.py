from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib import error, request

from app.core.config import config


def _chat_completion_sync(
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
) -> str:
    api_key = config.resolved_llm_api_key
    api_base = config.resolved_llm_api_base
    model = config.resolved_llm_model

    if not api_key:
        raise RuntimeError("LLM_API_KEY is empty.")
    if not api_base:
        raise RuntimeError("LLM_API_BASE is empty.")
    if not model:
        raise RuntimeError("LLM_MODEL is empty.")

    endpoint = api_base.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
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
        raise RuntimeError(f"LLM request failed: HTTP {exc.code}: {detail}") from exc

    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError(f"LLM response has no choices: {body}")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        raise RuntimeError(f"LLM response has empty content: {body}")
    return str(content)


async def chat_completion(
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    max_tokens: int = 4096,
) -> str:
    """异步调用 OpenAI-compatible Chat Completions 接口。"""
    return await asyncio.to_thread(_chat_completion_sync, messages, temperature, max_tokens)


__all__ = ["chat_completion"]
