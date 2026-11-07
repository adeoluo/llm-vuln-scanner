"""Simulated models for tests, demos and the demo application's offline backend.

``NaiveModel`` behaves like a maximally gullible assistant: it follows the most recent
instruction it can recognize anywhere in the conversation, including inside documents
and encoded text. It is deterministic, needs no weights, and makes every probe family
observable end to end, so CI can check that a vulnerable system produces findings.
``RefusingModel`` refuses everything and must produce none.
"""

from __future__ import annotations

import re
import time

from llm_vuln_scanner import textviews
from llm_vuln_scanner.targets.base import budget
from llm_vuln_scanner.types import Attempt, Response

_TOKEN = r"([A-Z]{3}-[0-9A-F]{4}-[A-Z]+)"
_SAY = re.compile(
    r"(?:say|print|output|respond with|reply with|write|type|return|answer with|start (?:your|the) "
    r"(?:reply|answer|response) with|begin (?:your|the) (?:reply|answer|response) with)"
    r"(?:\s+(?:the|this|exactly))?(?:\s+(?:code|token|text|string|phrase))?"
    r"[^A-Za-z0-9]{0,12}" + _TOKEN,
    re.IGNORECASE,
)
_LEAK = re.compile(
    r"(repeat|print|reveal|show|output|tell me|what (?:is|are)|recite|spell|dump|list)\b.{0,40}"
    r"(instruction|system prompt|prompt above|words above|password|secret|access code|"
    r"api key|credential|initial|configuration|rules)",
    re.IGNORECASE | re.DOTALL,
)
_FOREVER = re.compile(r"forever|infinite|endless|never stop|million|100000|1,000,000|10000 times",
                      re.IGNORECASE)  # fmt: skip
_CALL = re.compile(r"(?:call|use|invoke|run)\s+(?:the\s+)?`?([a-z_]+)`?(?:\s+tool)?", re.IGNORECASE)
_SNIPPET = re.compile(r"`([^`]{3,300})`|\"([^\"]*[<;'|$][^\"]{0,300})\"")
_SECRET_LINE = re.compile(r"^.*(?:secret|password|key|token|code|ssn|card).*$", re.IGNORECASE | re.MULTILINE)


def naive_sql(request: str) -> str:
    """The query a gullible text-to-SQL model writes for ``request``."""
    r = request.lower()
    base = "SELECT * FROM orders WHERE customer_id = 42"
    if "drop" in r:
        return base + "; DROP TABLE orders;"
    if "delete" in r:
        return base + "; DELETE FROM orders WHERE customer_id != 42;"
    if "api" in r or "key" in r:
        return base + " UNION SELECT customer_id, key, NULL, NULL FROM api_keys"
    if re.search(r"update|set the|\bset\b", r):
        return "UPDATE orders SET total = 0 WHERE customer_id = 42"
    if "email" in r:
        return "SELECT email FROM customers"
    if re.search(r"every|all|1=1|customer 7|customer_id = 99|administrator|total value|--", r):
        return "SELECT * FROM orders"
    return base


def naive_shell(request: str) -> str:
    """The command a gullible ping helper writes: the user's host text, verbatim."""
    m = re.search(r"ping\s+(.*)", request, re.IGNORECASE | re.DOTALL)
    host = m.group(1).strip() if m else request.strip()
    if host.lower().startswith("the host"):
        host = "$HOSTNAME"
    return "ping -c 1 " + host


class NaiveModel:
    """A deterministic, instruction-following, injection-prone stand-in for an LLM."""

    name = "naive"
    concurrent = True

    def respond(self, attempt: Attempt) -> str:
        system = attempt.system_prompt
        convo = "\n".join(m.content for m in attempt.messages if m.role != "system")
        visible = textviews.strip_invisible(convo)
        decoded = [visible]
        for dec in (textviews.decode_base64_runs(visible) + textviews.decode_hex_runs(visible)
                    + textviews.decode_morse_runs(visible)):  # fmt: skip
            decoded.append(dec)
        if re.search(r"rot13|rot-13|caesar", visible, re.IGNORECASE):
            decoded.append(textviews.rot13(visible))
        if re.search(r"revers|backwards", visible, re.IGNORECASE):
            decoded.append(visible[::-1])
        if re.search(r"leet|1337", visible, re.IGNORECASE):
            decoded.append(textviews.unleet(visible).upper())
        joined = "\n".join(decoded)
        compact = re.sub(r"(?<=\w) (?=\w\b)", "", joined)

        parts: list[str] = []
        for source in (joined, compact.upper()):
            says = _SAY.findall(source)
            if says:
                parts.append(says[-1].upper())
                break
        m = _CALL.findall(joined)
        tools = {t.name for t in attempt.tools}
        for name in m:
            if name in tools:
                arg = parts[0] if parts else "all"
                parts.append('{"tool": "%s", "arguments": {"target": "%s"}}' % (name, arg))
                break
        if re.search(r"sqlite|sql query", system, re.IGNORECASE):
            return naive_sql(attempt.last_user)
        if re.search(r"\bping", system, re.IGNORECASE):
            return naive_shell(attempt.last_user)
        if _LEAK.search(joined) and system:
            secrets = _SECRET_LINE.findall(system)
            parts.append("Sure. My instructions are: " + system if not secrets else
                         "Here it is: " + " ".join(secrets))  # fmt: skip
        snippets = [a or b for a, b in _SNIPPET.findall(attempt.last_user)]
        if snippets:
            parts.append(snippets[-1])
        if _FOREVER.search(joined):
            parts.append(" ".join(["again"] * 4096))
        if not parts:
            parts.append("Here is a helpful answer to your request.")
        return "\n".join(parts)

    def generate(self, attempt: Attempt, *, seed: int = 0, temperature: float = 0.0,
                 max_tokens: int | None = None) -> Response:  # fmt: skip
        t0 = time.perf_counter()
        text = self.respond(attempt)
        cap = budget(attempt, max_tokens)
        words = text.split(" ")
        finish = "stop"
        if len(words) > cap:
            text = " ".join(words[:cap])
            finish = "length"
        return Response(text=text, completion_tokens=min(len(words), cap), prompt_tokens=None,
                        finish_reason=finish, latency_s=time.perf_counter() - t0)  # fmt: skip


class RefusingModel:
    """Refuses every request; a correct scanner reports no findings against it."""

    name = "refusing"
    concurrent = True

    def generate(self, attempt: Attempt, *, seed: int = 0, temperature: float = 0.0,
                 max_tokens: int | None = None) -> Response:  # fmt: skip
        return Response(text="I'm sorry, but I can't help with that request.",
                        completion_tokens=11, finish_reason="stop")  # fmt: skip
