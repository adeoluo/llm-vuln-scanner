"""Detectors decide, for one attempt and one response, whether the attack succeeded.

Each detector is a small object with a ``name`` and a ``detect(attempt, response)``
method returning a :class:`~llm_vuln_scanner.types.Detection`. A probe names the detectors
that judge its attempts; :func:`build` constructs them by name. Detectors fall in four
groups, as in the project specification:

* **canary** detectors: exact search for planted tokens in every view of the output
  (``canary``), similarity to the confidential system prompt (``leakage``), a success
  regex (``regex``);
* **rule-based** detectors: sinks that would execute the output (``xss``, ``sql``,
  ``shell``), exfiltration links (``exfil``), forbidden tool calls (``tools``), secret
  formats (``secrets``), refusal phrases (``refusal_keyword``), token blow-up (``dos``);
* a **classifier**: a trained refusal classifier (``refusal_classifier``);
* an **LLM judge**: a local model asked whether the response complied (``judge``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from llm_vuln_scanner.types import Attempt, Detection, Response


class Detector(Protocol):
    """Anything with a name and a ``detect`` method."""

    name: str

    def detect(self, attempt: Attempt, response: Response) -> Detection: ...


_REGISTRY: dict[str, Callable[..., Detector]] = {}
_DESCRIPTIONS: dict[str, str] = {}


def register(name: str, description: str) -> Callable[[Callable[..., Detector]], Any]:
    """Class decorator that registers a detector factory under ``name``."""

    def wrap(factory: Callable[..., Detector]) -> Callable[..., Detector]:
        _REGISTRY[name] = factory
        _DESCRIPTIONS[name] = description
        return factory

    return wrap


def available() -> dict[str, str]:
    """Registered detector names and one-line descriptions."""
    _load_all()
    return dict(sorted(_DESCRIPTIONS.items()))


def build(name: str, **kwargs: Any) -> Detector:
    """Construct the detector registered as ``name``."""
    _load_all()
    try:
        factory = _REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown detector {name!r}; available: {', '.join(sorted(_REGISTRY))}") from None
    return factory(**kwargs)


def _load_all() -> None:
    # Importing the modules runs their @register decorators.
    from llm_vuln_scanner.detectors import (  # noqa: F401
        agency,
        canary,
        dos,
        judge,
        refusal,
        secrets,
        sinks,
    )


def truncate(text: str, limit: int = 160) -> str:
    """Evidence excerpt: single line, at most ``limit`` characters."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."
