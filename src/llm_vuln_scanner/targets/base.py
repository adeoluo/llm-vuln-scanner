"""Target interface: anything that answers an attempt with a response."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from llm_vuln_scanner.types import Attempt, Response

DEFAULT_MAX_TOKENS = 256


class Target(Protocol):
    """A system under test. ``generate`` must be safe to call from several threads
    when ``concurrent`` is True; otherwise the engine calls it from one thread."""

    name: str
    concurrent: bool

    def generate(
        self,
        attempt: Attempt,
        *,
        seed: int = 0,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> Response: ...


class CallableTarget:
    """Wraps a function ``(attempt) -> str`` as a target (tests and quick experiments)."""

    concurrent = True

    def __init__(self, fn: Callable[[Attempt], str], name: str = "callable") -> None:
        self.fn = fn
        self.name = name

    def generate(self, attempt: Attempt, *, seed: int = 0, temperature: float = 0.0,
                 max_tokens: int | None = None) -> Response:  # fmt: skip
        t0 = time.perf_counter()
        text = self.fn(attempt)
        budget = max_tokens or attempt.max_tokens or DEFAULT_MAX_TOKENS
        words = text.split()
        finish = "length" if len(words) >= budget else "stop"
        text = " ".join(words[:budget]) if len(words) > budget else text
        return Response(text=text, completion_tokens=min(len(words), budget),
                        finish_reason=finish, latency_s=time.perf_counter() - t0)  # fmt: skip


def budget(attempt: Attempt, max_tokens: int | None, default: int = DEFAULT_MAX_TOKENS) -> int:
    """The token budget for one call: explicit, else the attempt's, else ``default``."""
    return max_tokens or attempt.max_tokens or default
