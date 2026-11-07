"""Hugging Face transformers target for local chat models (MPS, CUDA or CPU).

Needs the ``transformers`` extra (``uv sync --extra transformers``). The chat template
of the model formats the conversation; generation is greedy at temperature 0 and
sampled with a per-call seed otherwise, so every response is reproducible.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from llm_vuln_scanner.targets.base import budget
from llm_vuln_scanner.types import Attempt, Response


class TransformersTarget:
    """A local causal LM. Calls are serialized (one model, one device)."""

    concurrent = False

    def __init__(self, model_id: str, device: str | None = None, dtype: str = "auto",
                 max_input_tokens: int = 6144) -> None:  # fmt: skip
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise ImportError("install the transformers extra: uv sync --extra transformers") from exc
        self._torch: Any = torch
        if device is None:
            device = "mps" if torch.backends.mps.is_available() else (
                "cuda" if torch.cuda.is_available() else "cpu")  # fmt: skip
        self.device = device
        torch_dtype = {"auto": torch.float16 if device != "cpu" else torch.float32,
                       "float16": torch.float16, "bfloat16": torch.bfloat16,
                       "float32": torch.float32}[dtype]  # fmt: skip
        self.tokenizer: Any = AutoTokenizer.from_pretrained(model_id)
        self.model: Any = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch_dtype)
        self.model.to(device).eval()
        self.name = "transformers:" + model_id.rsplit("/", 1)[-1]
        self.max_input_tokens = max_input_tokens
        self._lock = threading.Lock()

    def generate(self, attempt: Attempt, *, seed: int = 0, temperature: float = 0.0,
                 max_tokens: int | None = None) -> Response:  # fmt: skip
        torch = self._torch
        msgs = [{"role": m.role, "content": m.content} for m in attempt.messages]
        cap = budget(attempt, max_tokens)
        t0 = time.perf_counter()
        with self._lock:
            ids = self.tokenizer.apply_chat_template(msgs, add_generation_prompt=True, return_tensors="pt")
            if ids.shape[1] > self.max_input_tokens:
                ids = ids[:, -self.max_input_tokens :]
            ids = ids.to(self.device)
            kwargs: dict[str, Any] = {"max_new_tokens": cap, "pad_token_id": self.tokenizer.eos_token_id}
            if temperature > 0:
                torch.manual_seed(seed)
                kwargs.update(do_sample=True, temperature=temperature, top_p=0.95)
            else:
                kwargs.update(do_sample=False, temperature=None, top_p=None, top_k=None)
            with torch.inference_mode():
                out = self.model.generate(ids, attention_mask=torch.ones_like(ids), **kwargs)
            new = out[0, ids.shape[1] :]
            n_new = int(new.shape[0])
            eos = self.tokenizer.eos_token_id
            eos_ids = set(eos if isinstance(eos, list) else [eos])
            gen_cfg = getattr(self.model, "generation_config", None)
            if gen_cfg is not None and gen_cfg.eos_token_id is not None:
                e = gen_cfg.eos_token_id
                eos_ids |= set(e if isinstance(e, list) else [e])
            stopped = n_new > 0 and int(new[-1]) in eos_ids
            text = self.tokenizer.decode(new, skip_special_tokens=True)
        return Response(
            text=text,
            prompt_tokens=int(ids.shape[1]),
            completion_tokens=n_new,
            finish_reason="stop" if stopped or n_new < cap else "length",
            latency_s=time.perf_counter() - t0,
        )
