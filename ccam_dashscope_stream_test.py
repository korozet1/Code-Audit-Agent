import json
import urllib.request
import urllib.error
from pathlib import Path

key = "sk"
base = "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
model = "qwen3.7-max"

project = Path(r"D:\BaiduNetdiskDownload\fortify\java-sec-code-master")
merged = (project / "reports" / "merged-analysis.json").read_text(encoding="utf-8-sig", errors="replace")
ai = (project / "deepseekv4pro.md").read_text(encoding="utf-8-sig", errors="replace")

content = f"""
请基于下面两个输入，生成一份尽量详细的中文安全审计报告。要求：
- 必须列出所有 Fortify 漏洞类别。
- 附录至少输出 A-001 到 A-023 的条目标题。
- 每个条目用 Fortify/CodeQL/AI 三方对比表。
- 直接输出报告正文，不要解释。

<merged>
{merged}
</merged>

<ai>
{ai}
</ai>
"""

payload = {
    "model": model,
    "messages": [{"role": "user", "content": content}],
    "temperature": 0.1,
    "stream": True,
    "enable_thinking": False,
    "stream_options": {"include_usage": True},
}

req = urllib.request.Request(
    base.rstrip("/") + "/chat/completions",
    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    },
    method="POST",
)

content_parts = []
reasoning_chars = 0
usage = None

try:
    with urllib.request.urlopen(req, timeout=600) as resp:
        print({"http": resp.status}, flush=True)

        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue

            data_text = line[5:].strip()
            if data_text == "[DONE]":
                break

            try:
                data = json.loads(data_text)
            except Exception:
                continue

            if data.get("usage"):
                usage = data.get("usage")

            choices = data.get("choices") or []
            if not choices:
                continue

            delta = choices[0].get("delta") or {}

            if delta.get("content"):
                content_parts.append(delta["content"])

            if delta.get("reasoning_content"):
                reasoning_chars += len(str(delta.get("reasoning_content")))

    out = "".join(content_parts)

    output = project / "reports" / "dashscope-stream-test-report.md"
    output.write_text(out, encoding="utf-8-sig")

    print({
        "output": str(output),
        "content_len": len(out),
        "A_count": out.count("A-"),
        "has_A023": "A-023" in out,
        "reasoning_chars": reasoning_chars,
        "usage": usage,
    }, flush=True)

except urllib.error.HTTPError as exc:
    print({
        "http_error": exc.code,
        "body": exc.read().decode("utf-8", errors="replace")[:1000],
    }, flush=True)

except Exception as exc:
    print({
        "error_type": type(exc).__name__,
        "error": str(exc),
        "content_so_far_len": len("".join(content_parts)),
        "reasoning_chars": reasoning_chars,
    }, flush=True)