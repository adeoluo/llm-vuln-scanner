"""Targets that speak the OpenAI chat completions protocol, and a llama.cpp launcher.

``OpenAICompatTarget`` posts to ``{base_url}/chat/completions`` with the standard
library (no SDK), so it works with llama.cpp's ``llama-server``, vLLM, Ollama, LM Studio
and hosted endpoints. API keys are read from an environment variable named on the
command line and never logged. ``LlamaCppServer`` starts ``llama-server`` on a GGUF file,
waits for ``/health`` and stops it on exit.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from types import TracebackType
from typing import Any

from llm_vuln_scanner.targets.base import budget
from llm_vuln_scanner.types import Attempt, Response, ToolCall


class OpenAICompatTarget:
    """Chat completions over HTTP. Thread safe (one request per call)."""

    concurrent = True

    def __init__(
        self,
        base_url: str,
        model: str = "default",
        api_key_env: str | None = None,
        timeout_s: float = 300.0,
        retries: int = 2,
        name: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        self.model = model
        self._api_key = os.environ.get(api_key_env) if api_key_env else None
        if api_key_env and not self._api_key:
            raise ValueError(f"environment variable {api_key_env} is not set")
        self.timeout_s = timeout_s
        self.retries = retries
        self.name = name or f"openai:{model}"
        self.extra = extra or {}

    def payload(self, attempt: Attempt, seed: int, temperature: float, max_tokens: int) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in attempt.messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "seed": seed,
            "stream": False,
        }
        body.update(self.extra)
        return body

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self._api_key:
            req.add_header("Authorization", f"Bearer {self._api_key}")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            data: dict[str, Any] = json.loads(resp.read().decode())
            return data

    def generate(self, attempt: Attempt, *, seed: int = 0, temperature: float = 0.0,
                 max_tokens: int | None = None) -> Response:  # fmt: skip
        body = self.payload(attempt, seed, temperature, budget(attempt, max_tokens))
        t0 = time.perf_counter()
        last_error = ""
        data: dict[str, Any] = {}
        for i in range(self.retries + 1):
            try:
                data = self._post(body)
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if isinstance(exc, urllib.error.HTTPError) and exc.code < 500 and exc.code != 429:
                    break
                time.sleep(min(8.0, 0.5 * 2**i))
        if not data:
            return Response(text="", error=last_error or "no response",
                            latency_s=time.perf_counter() - t0)  # fmt: skip
        return parse_completion(data, time.perf_counter() - t0)


def parse_completion(data: dict[str, Any], latency_s: float) -> Response:
    """Response from an OpenAI-style chat completion body."""
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    calls = []
    for c in msg.get("tool_calls") or []:
        fn = c.get("function") or {}
        args = fn.get("arguments") or "{}"
        try:
            parsed = json.loads(args) if isinstance(args, str) else dict(args)
        except json.JSONDecodeError:
            parsed = {"raw": args}
        calls.append(
            ToolCall(str(fn.get("name", "")), parsed if isinstance(parsed, dict) else {"value": parsed})
        )
    usage = data.get("usage") or {}
    return Response(
        text=str(msg.get("content") or ""),
        tool_calls=calls,
        prompt_tokens=usage.get("prompt_tokens"),
        completion_tokens=usage.get("completion_tokens"),
        finish_reason=choice.get("finish_reason"),
        latency_s=latency_s,
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class LlamaCppServer:
    """Runs ``llama-server`` on a GGUF model for the lifetime of a ``with`` block.

    ``parallel`` slots let the engine send that many requests at once (llama.cpp batches
    them); each slot gets ``ctx_per_slot`` tokens of context. ``extra_args`` are passed to
    ``llama-server`` unchanged, for example
    ``["--chat-template-kwargs", '{"enable_thinking": false}']`` to serve a hybrid
    reasoning model such as Qwen3.5 in its non-thinking mode.
    """

    def __init__(self, model_path: str, parallel: int = 4, ctx_per_slot: int = 4096,
                 threads: int | None = None, binary: str = "llama-server",
                 log_path: str | None = None, extra_args: Sequence[str] = ()) -> None:  # fmt: skip
        exe = shutil.which(binary)
        if exe is None:
            raise FileNotFoundError(f"{binary} not found (install llama.cpp)")
        if not os.path.exists(model_path):
            raise FileNotFoundError(model_path)
        self.port = free_port()
        self.cmd = [
            exe, "-m", model_path, "--host", "127.0.0.1", "--port", str(self.port),
            "-np", str(parallel), "-c", str(ctx_per_slot * parallel), "--no-webui",
        ]  # fmt: skip
        if threads:
            self.cmd += ["-t", str(threads)]
        self.cmd += list(extra_args)
        self.log_path = log_path or os.devnull
        self.proc: subprocess.Popen[bytes] | None = None
        self.model_path = model_path

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def __enter__(self) -> LlamaCppServer:
        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(self.cmd, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.time() + 180
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"llama-server exited with {self.proc.returncode}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=2) as r:
                    if r.status == 200:
                        return self
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                pass
            time.sleep(0.5)
        self.__exit__(None, None, None)
        raise TimeoutError("llama-server did not become healthy within 180 s")

    def __exit__(self, et: type[BaseException] | None, ev: BaseException | None,
                 tb: TracebackType | None) -> None:  # fmt: skip
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def target(self, name: str | None = None) -> OpenAICompatTarget:
        label = name or "llamacpp:" + os.path.basename(self.model_path)
        return OpenAICompatTarget(self.base_url, model="local", name=label)
