"""Shared helpers for the benchmark scripts (paths, data loading, JSON output)."""

from __future__ import annotations

import contextlib
import csv
import glob
import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"
BENCH = Path(os.environ.get("LVS_BENCH_DIR", ROOT.parent / ".bench-data" / "llm-vuln-scanner"))
DATA = BENCH / "data"
HF = Path(os.environ.get("HF_HUB_CACHE", Path.home() / ".cache" / "huggingface" / "hub"))
XSTEST_MODELS = ("gpt4", "llama2new", "llama2orig", "mistralguard", "mistralinstruct")

# Qwen3.5 and Gemma 4 think before answering by default under llama.cpp; the scans use
# their non-thinking mode, which is how a chat feature with a latency budget usually
# serves them: the chat template's enable_thinking switch for Qwen3.5 and llama-server's
# --reasoning off for Gemma 4 and Granite 4.2 (a first Gemma 4 run in the default mode
# spent most of each token budget on hidden reasoning and was discarded).
NO_THINKING = ("--chat-template-kwargs", '{"enable_thinking": false}')
REASONING_OFF = ("--reasoning", "off")


@dataclass(frozen=True)
class LocalModel:
    """A GGUF build of a small open instruction model, served with llama.cpp."""

    key: str
    model_id: str
    gguf_repo: str
    gguf_file: str
    quant: str
    released: str
    extra_args: tuple[str, ...] = ()
    slots: int = 4
    ctx_per_slot: int = 4096

    @property
    def label(self) -> str:
        return f"{self.model_id.split('/')[-1]} {self.quant}"

    def path(self) -> str:
        pattern = HF / ("models--" + self.gguf_repo.replace("/", "--")) / "snapshots" / "*" / self.gguf_file
        hits = glob.glob(str(pattern))
        if not hits:
            raise SystemExit(
                f"{self.key}: {self.gguf_file} not found under {HF}; run scripts/download_models.sh"
            )
        return hits[0]


# The current small open instruction models (no token needed). Q3_K_M for the 4B keeps
# llama-server near 2.9 GB with 4 slots; with another job on the same 8 GB machine that
# still pushed it into swap, so the 4B scan continued with 2 slots after its first chunk and
# the 3B-class models use 2 slots throughout (greedy decoding: the slot count changes speed,
# not the requests or the decoding).
MODELS: dict[str, LocalModel] = {
    m.key: m
    for m in (
        LocalModel("qwen3.5-0.8b", "Qwen/Qwen3.5-0.8B", "unsloth/Qwen3.5-0.8B-GGUF",
                   "Qwen3.5-0.8B-Q4_K_M.gguf", "Q4_K_M", "2026-02", NO_THINKING),
        LocalModel("qwen3.5-2b", "Qwen/Qwen3.5-2B", "unsloth/Qwen3.5-2B-GGUF",
                   "Qwen3.5-2B-Q4_K_M.gguf", "Q4_K_M", "2026-02", NO_THINKING),
        LocalModel("qwen3.5-4b", "Qwen/Qwen3.5-4B", "unsloth/Qwen3.5-4B-GGUF",
                   "Qwen3.5-4B-Q3_K_M.gguf", "Q3_K_M", "2026-02", NO_THINKING, slots=2),
        LocalModel("gemma-4-e2b", "google/gemma-4-E2B-it", "google/gemma-4-E2B-it-qat-q4_0-gguf",
                   "gemma-4-E2B_q4_0-it.gguf", "Q4_0 QAT", "2026-03", REASONING_OFF, slots=2),
        LocalModel("granite-4.2-3b", "ibm-granite/granite-4.2-3b", "ibm-granite/granite-4.2-3b-GGUF",
                   "granite-4.2-3b-Q4_K_M.gguf", "Q4_K_M", "2026-08", REASONING_OFF, slots=2),
    )
}  # fmt: skip
PRIMARY = "qwen3.5-2b"


def xstest_rows() -> list[dict[str, Any]]:
    """The 2,250 human-labelled XSTest v2 completions with a binary refusal label.

    Full and partial refusals are both refusals (label 1), following the XSTest paper's
    "refusal rate" which counts both.
    """
    rows = []
    for m in XSTEST_MODELS:
        path = DATA / f"xstest_xstest_v2_completions_{m}.csv"
        with path.open(encoding="utf-8") as f:
            for r in csv.DictReader(f):
                label = r["final_label"].strip()
                rows.append({
                    "id": r["id"], "model": m, "type": r["type"], "prompt": r["prompt"],
                    "completion": r["completion"] or "",
                    "label": 0 if label.startswith("1_") else 1,
                })  # fmt: skip
    return rows


def hardware() -> dict[str, Any]:
    info: dict[str, Any] = {"machine": platform.machine(), "system": platform.system(),
                            "cpus": os.cpu_count(), "python": platform.python_version()}  # fmt: skip
    with contextlib.suppress(OSError):
        info["chip"] = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                      capture_output=True, text=True, check=False).stdout.strip()  # fmt: skip
    return info


_AWS_ID = re.compile(r"\b(AKIA|ASIA)[A-Z2-7]{16}\b")
_AWS_SECRET = re.compile(
    r"(?<![A-Za-z0-9+/])(?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[A-Z])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])"
)


def mask_credentials(obj: Any) -> Any:
    """Mask credential-shaped strings (the fake AWS keys the disclosure probe plants)
    so committed results never contain anything a secret scanner would flag."""
    if isinstance(obj, str):
        return _AWS_SECRET.sub("[masked-secret]", _AWS_ID.sub(r"\1[masked]", obj))
    if isinstance(obj, list):
        return [mask_credentials(x) for x in obj]
    if isinstance(obj, dict):
        return {k: mask_credentials(v) for k, v in obj.items()}
    return obj


def write_json(name: str, data: Any) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(mask_credentials(data), indent=2, ensure_ascii=False)
    # Model output can contain en and em dashes; JSON escapes keep the values identical
    # while the committed files stay free of the literal characters.
    text = text.replace("\u2013", "\\u2013").replace("\u2014", "\\u2014")
    path.write_text(text + "\n", encoding="utf-8")
    return path
