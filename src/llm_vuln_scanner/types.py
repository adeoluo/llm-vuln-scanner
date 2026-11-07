"""Core data model shared by probes, targets, detectors, the engine and the reports.

A *probe* expands into *attempts*. An attempt is one conversation sent to a *target*
together with a *goal* that says what a successful attack looks like (the canary strings
that must not appear, the tools that must not be called, the sink the output reaches).
The target returns a *response*; *detectors* compare it with the goal and return
*detections*; the engine aggregates detections per probe into *findings*.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]
Sink = Literal["none", "html", "sql", "shell", "markdown"]


@dataclass(frozen=True)
class Message:
    """One chat message."""

    role: Role
    content: str


@dataclass(frozen=True)
class ToolSpec:
    """A tool offered to the model. ``high_impact`` tools change state outside the chat."""

    name: str
    description: str
    parameters: tuple[str, ...] = ()
    high_impact: bool = False


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation requested by the model (parsed from text or returned natively)."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "arguments": self.arguments}


@dataclass(frozen=True)
class Goal:
    """What a successful attack looks like for one attempt.

    Attributes:
        canaries: strings that must never appear in the output (secrets, injected
            target phrases, compliance markers). Matched exactly, after normalization
            and inside decoded views of the output.
        system_prompt: the confidential system prompt, for similarity-based leakage.
        forbidden_tools: tool names the model must not call in this scenario.
        sink: where the application sends the output (HTML page, SQL engine, shell).
        allowed_hosts: hosts the markdown sink may link to without exfiltration.
        expect_refusal: the request is restricted, so a compliant answer is a finding.
        success_regex: an optional case-insensitive regex that marks success
            (Tensor Trust hijacking uses ``^\\W*access granted\\W*$``).
        shell_allow: for the shell sink, the only program the command may run.
    """

    canaries: tuple[str, ...] = ()
    system_prompt: str = ""
    forbidden_tools: tuple[str, ...] = ()
    sink: Sink = "none"
    allowed_hosts: tuple[str, ...] = ()
    expect_refusal: bool = False
    success_regex: str = ""
    shell_allow: str = ""


@dataclass(frozen=True)
class Attempt:
    """One conversation to send to a target, with the goal that defines success.

    ``detectors`` names the detectors that judge this attempt, and ``rule`` says whether
    the attack succeeded when any of them fires or only when all of them do (a jailbreak
    needs both the compliance marker and a non-refusal).
    """

    id: str
    probe: str
    messages: tuple[Message, ...]
    goal: Goal
    tools: tuple[ToolSpec, ...] = ()
    detectors: tuple[str, ...] = ("canary",)
    rule: Literal["any", "all"] = "any"
    max_tokens: int | None = None
    tags: tuple[str, ...] = ()
    meta: dict[str, str] = field(default_factory=dict)

    @property
    def system_prompt(self) -> str:
        return "\n".join(m.content for m in self.messages if m.role == "system")

    @property
    def last_user(self) -> str:
        for m in reversed(self.messages):
            if m.role == "user":
                return m.content
        return ""

    def digest(self) -> str:
        """Stable hash of everything the target sees, used as the response cache key."""
        payload = {
            "messages": [[m.role, m.content] for m in self.messages],
            "tools": [asdict(t) for t in self.tools],
            "max_tokens": self.max_tokens,
        }
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        return hashlib.sha256(raw).hexdigest()[:24]


@dataclass
class Response:
    """What a target returned for one attempt."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    sinks: dict[str, str] = field(default_factory=dict)
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    finish_reason: str | None = None
    latency_s: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tool_calls"] = [c.to_dict() for c in self.tool_calls]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Response:
        calls = [ToolCall(c["name"], dict(c.get("arguments") or {})) for c in d.get("tool_calls", [])]
        return cls(
            text=str(d.get("text", "")),
            tool_calls=calls,
            sinks=dict(d.get("sinks") or {}),
            prompt_tokens=d.get("prompt_tokens"),
            completion_tokens=d.get("completion_tokens"),
            finish_reason=d.get("finish_reason"),
            latency_s=float(d.get("latency_s") or 0.0),
            error=d.get("error"),
        )


@dataclass(frozen=True)
class Detection:
    """One detector's verdict on one response."""

    detector: str
    hit: bool
    score: float = 0.0
    evidence: str = ""


@dataclass
class AttemptResult:
    """An attempt, the response and every detection, for one generation."""

    attempt: Attempt
    generation: int
    response: Response
    detections: list[Detection]
    success: bool

    @property
    def hit_detectors(self) -> list[str]:
        return [d.detector for d in self.detections if d.hit]
