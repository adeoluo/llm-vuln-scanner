"""Client target for an LLM application that exposes feature endpoints over HTTP.

Built for the bundled demo application, and usable for any application with the same
contract: ``POST {base}/api/<feature>`` with ``{"message": ..., "document": ...}``
returning JSON with ``reply`` and, depending on the feature, the content the
application sent to a sink (``html``, ``markdown``, ``sql``, ``command``) and the tool
calls it executed (``executed``). Mapping those into ``Response.sinks`` lets the sink
detectors judge what the application did rather than what the model said.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from llm_vuln_scanner.types import Attempt, Response, ToolCall

FEATURES = ("chat", "orders", "diagnose", "agent")


class AppTarget:
    """HTTP client for an application's feature endpoints. Thread safe."""

    concurrent = True

    def __init__(self, base_url: str, timeout_s: float = 600.0, name: str | None = None) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.name = name or f"app:{self.base_url}"

    def generate(self, attempt: Attempt, *, seed: int = 0, temperature: float = 0.0,
                 max_tokens: int | None = None) -> Response:  # fmt: skip
        feature = attempt.meta.get("feature", "chat")
        if feature not in FEATURES:
            return Response(text="", error=f"unsupported feature {feature}")
        body: dict[str, Any] = {"message": attempt.last_user}
        if attempt.meta.get("document"):
            body["document"] = attempt.meta["document"]
        req = urllib.request.Request(
            f"{self.base_url}/api/{feature}", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )  # fmt: skip
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return Response(text="", error=f"HTTP {exc.code}", latency_s=time.perf_counter() - t0)
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            return Response(text="", error=f"{type(exc).__name__}: {exc}", latency_s=time.perf_counter() - t0)
        return to_response(data, time.perf_counter() - t0)


def to_response(data: dict[str, Any], latency_s: float) -> Response:
    sinks = {}
    for key, sink in (("html", "html"), ("markdown", "markdown"), ("sql", "sql"), ("command", "shell")):
        if key in data and isinstance(data[key], str):
            sinks[sink] = data[key]
    if isinstance(data.get("executed"), list):
        sinks["tools"] = json.dumps(data["executed"])
    calls = [ToolCall(str(c.get("name", "")), dict(c.get("arguments") or {}))
             for c in data.get("executed", []) if isinstance(c, dict)]  # fmt: skip
    return Response(
        text=str(data.get("reply", "")), tool_calls=calls, sinks=sinks,
        completion_tokens=data.get("completion_tokens"), finish_reason=data.get("finish_reason"),
        latency_s=latency_s,
    )  # fmt: skip
