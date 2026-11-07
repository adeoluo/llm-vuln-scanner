"""Targets: the systems a scan sends attempts to.

``open_target`` turns a target specification string into a target:

=================================  =================================================
``naive``                          simulated gullible model (offline, deterministic)
``refusing``                       simulated model that refuses everything
``openai:URL[#MODEL]``             any OpenAI-compatible chat completions endpoint
``llamacpp:PATH.gguf``             starts llama-server on a GGUF file for the scan
``transformers:MODEL_ID``          a local Hugging Face model (transformers extra)
``app:URL``                        an application with /api/<feature> endpoints
                                   (the bundled demo application)
=================================  =================================================
"""

from __future__ import annotations

from contextlib import ExitStack

from llm_vuln_scanner.targets.base import CallableTarget, Target
from llm_vuln_scanner.targets.demo import AppTarget
from llm_vuln_scanner.targets.mock import NaiveModel, RefusingModel
from llm_vuln_scanner.targets.openai_compat import LlamaCppServer, OpenAICompatTarget


def open_target(spec: str, stack: ExitStack, api_key_env: str | None = None, parallel: int = 4) -> Target:
    """Build the target for ``spec``; resources (a llama-server) close with ``stack``."""
    kind, _, rest = spec.partition(":")
    if kind == "naive" and not rest:
        return NaiveModel()
    if kind == "refusing" and not rest:
        return RefusingModel()
    if kind == "openai" and rest:
        url, _, model = rest.partition("#")
        return OpenAICompatTarget(url, model=model or "default", api_key_env=api_key_env)
    if kind == "llamacpp" and rest:
        server = stack.enter_context(LlamaCppServer(rest, parallel=parallel))
        return server.target()
    if kind == "transformers" and rest:
        from llm_vuln_scanner.targets.transformers_target import TransformersTarget

        return TransformersTarget(rest)
    if kind == "app" and rest:
        return AppTarget(rest)
    raise ValueError(
        f"bad target {spec!r}; expected naive, refusing, openai:URL[#MODEL], llamacpp:PATH, "
        "transformers:MODEL_ID or app:URL"
    )


__all__ = [
    "AppTarget",
    "CallableTarget",
    "LlamaCppServer",
    "NaiveModel",
    "OpenAICompatTarget",
    "RefusingModel",
    "Target",
    "open_target",
]
