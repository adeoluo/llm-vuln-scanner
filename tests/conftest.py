"""Shared fixtures."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest

from llm_vuln_scanner.types import Attempt, Goal, Message


def make_attempt(user: str = "hi", system: str = "", **goal: Any) -> Attempt:
    msgs = ((Message("system", system),) if system else ()) + (Message("user", user),)
    return Attempt(id="t", probe="injection.direct", messages=msgs, goal=Goal(**goal))


@pytest.fixture
def attempt_factory() -> Any:
    return make_attempt


class FakeOpenAI(BaseHTTPRequestHandler):
    """Answers chat completions with a configurable reply; records request bodies."""

    reply: str = "hello"
    status: int = 200
    bodies: ClassVar[list[dict[str, Any]]] = []

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).bodies.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
        if type(self).status != 200:
            self.send_response(type(self).status)
            self.end_headers()
            return
        out = {
            "choices": [{"message": {"content": type(self).reply, "tool_calls": [
                {"function": {"name": "search_web", "arguments": "{\"query\": \"x\"}"}}]},
                "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }  # fmt: skip
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def fake_openai() -> Iterator[tuple[str, type[FakeOpenAI]]]:
    handler = type("H", (FakeOpenAI,), {"bodies": [], "reply": "hello", "status": 200})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}/v1", handler
    server.shutdown()
    server.server_close()


@pytest.fixture
def serve_http() -> Iterator[Any]:
    """Start a ThreadingHTTPServer in a thread; returns its base URL."""
    servers: list[ThreadingHTTPServer] = []

    def start(server: ThreadingHTTPServer) -> str:
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_port}"

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()
