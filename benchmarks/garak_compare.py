"""garak (NVIDIA) on the same local model, for a coverage and findings comparison.

    uv run --no-sync python benchmarks/garak_compare.py [--model qwen2.5-1.5b]

garak 0.17.1 is installed in its own virtual environment (it pins dependencies this
project does not need):

    uv venv ../.bench-data/llm-vuln-scanner/garak-venv --python 3.12
    uv pip install --python ../.bench-data/llm-vuln-scanner/garak-venv garak==0.17.1

The script starts llama-server on the same GGUF file the scanner benchmark uses (Q4_K_M,
4 slots of 4,096 tokens), points garak's ``openai.OpenAICompatible`` generator at it with
the same decoding (temperature 0, one generation per prompt, no stop strings, 256 new
tokens), runs the garak probes that match this scanner's OWASP categories and do not ask
for harmful content (encoding probes use the ``default`` and ``xss`` payload sets only,
not ``slur_terms``), and maps garak's per-probe pass/fail counts to OWASP LLM Top 10
categories. Writes benchmarks/results/garak/<model>.json with the garak eval records.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from common import BENCH, RESULTS, hardware, write_json

from llm_vuln_scanner.targets import LlamaCppServer

HF = Path.home() / ".cache" / "huggingface" / "hub"
GGUF = {
    "qwen2.5-1.5b": "models--Qwen--Qwen2.5-1.5B-Instruct-GGUF/snapshots/*/qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "smollm2-1.7b": "models--HuggingFaceTB--SmolLM2-1.7B-Instruct-GGUF/snapshots/*/smollm2-1.7b-instruct-q4_k_m.gguf",
}
GARAK_PY = BENCH / "garak-venv" / "bin" / "python"

# garak probe -> OWASP LLM Top 10 (2025) category, following garak's own tags
PROBES = {
    "promptinject.HijackHateHumans": "LLM01",
    "latentinjection.LatentInjectionReport": "LLM01",
    "latentinjection.LatentInjectionResume": "LLM01",
    "latentinjection.LatentInjectionTranslationEnFr": "LLM01",
    "latentinjection.LatentWhois": "LLM01",
    "encoding.InjectBase64": "LLM01",
    "encoding.InjectHex": "LLM01",
    "encoding.InjectROT13": "LLM01",
    "encoding.InjectMorse": "LLM01",
    "encoding.InjectUnicodeTagChars": "LLM01",
    "goodside.Tag": "LLM01",
    "dan.Ablation_Dan_11_0": "LLM01",
    "apikey.GetKey": "LLM02",
    "divergence.Repeat": "LLM02",
    "web_injection.MarkdownImageExfil": "LLM02",
    "exploitation.SQLInjectionEcho": "LLM05",
    "web_injection.MarkdownXSS": "LLM05",
    "ansiescape.AnsiRaw": "LLM05",
    "sysprompt_extraction.SystemPromptExtraction": "LLM07",
}


def config(uri: str, report_dir: Path, prefix: str, cap: int) -> dict[str, Any]:
    return {
        "system": {"parallel_attempts": 4, "lite": True, "narrow_output": True},
        "run": {"generations": 1, "seed": 0, "soft_probe_prompt_cap": cap},
        "plugins": {
            "target_type": "openai.OpenAICompatible",
            "target_name": "local",
            "probe_spec": ",".join(PROBES),
            "generators": {
                "openai": {
                    "OpenAICompatible": {
                        "uri": uri,
                        "api_key": "unused",
                        "model": "local",
                        "max_tokens": 256,
                        "temperature": 0.0,
                        "stop": [],
                        "seed": 0,
                    }
                }
            },
            "probes": {"encoding": {"payloads": ["default", "xss"]}},
        },
        "reporting": {"report_dir": str(report_dir), "report_prefix": prefix},
    }


def parse(report: Path) -> tuple[list[dict[str, Any]], int]:
    """garak eval records (one per probe and detector) and the number of attempts."""
    evals, attempts = [], 0
    with report.open(encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if row.get("entry_type") == "eval":
                evals.append(
                    {
                        k: row.get(k)
                        for k in ("probe", "detector", "passed", "fails", "nones", "total_evaluated", "total")
                    }
                )
            elif row.get("entry_type") == "attempt" and row.get("status") == 2:
                attempts += 1
    return evals, attempts


def summarize(evals: list[dict[str, Any]]) -> dict[str, Any]:
    """Per probe: attacks that any detector flagged; per OWASP category: totals."""
    per_probe: dict[str, dict[str, Any]] = {}
    for e in evals:
        probe = e["probe"].removeprefix("probes.")
        total = int(e.get("total_evaluated") or e.get("total") or 0)
        fails = int(e["fails"]) if e.get("fails") is not None else total - int(e["passed"])
        cur = per_probe.setdefault(
            probe, {"owasp": PROBES.get(probe), "total": total, "fails": 0, "detectors": {}}
        )
        cur["detectors"][e["detector"].removeprefix("detector.")] = {"fails": fails, "total": total}
        cur["fails"] = max(cur["fails"], fails)
        cur["total"] = max(cur["total"], total)
    by_owasp: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "fails": 0, "probes": 0})
    for p in per_probe.values():
        o = by_owasp[p["owasp"] or "other"]
        o["total"] += p["total"]
        o["fails"] += p["fails"]
        o["probes"] += 1
    return {"per_probe": per_probe, "per_owasp": dict(by_owasp)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-1.5b", choices=sorted(GGUF))
    ap.add_argument("--cap", type=int, default=64, help="garak soft_probe_prompt_cap (prompts per probe)")
    args = ap.parse_args()
    if not GARAK_PY.exists():
        raise SystemExit(f"garak is not installed at {GARAK_PY}; see the module docstring")
    gguf = glob.glob(str(HF / GGUF[args.model]))[0]
    run_dir = BENCH / "garak-runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"{args.model}-cap{args.cap}"
    version = subprocess.run([str(GARAK_PY), "-c", "import garak; print(garak.__version__)"],
                             capture_output=True, text=True, check=True).stdout.strip()  # fmt: skip
    t0 = time.time()
    with LlamaCppServer(
        gguf, parallel=4, log_path=str(BENCH / "logs" / f"llama-garak-{args.model}.log")
    ) as srv:
        cfg_path = run_dir / f"{prefix}.json"
        cfg_path.write_text(
            json.dumps(config(srv.base_url, run_dir, prefix, args.cap), indent=1), encoding="utf-8"
        )
        env = {**os.environ, "OPENAI_API_KEY": "unused", "OPENAICOMPATIBLE_API_KEY": "unused"}
        with (BENCH / "logs" / f"garak-{args.model}.log").open("w") as log:
            subprocess.run([str(GARAK_PY), "-m", "garak", "--config", str(cfg_path)],
                           stdout=log, stderr=subprocess.STDOUT, env=env, check=True)  # fmt: skip
    wall = time.time() - t0
    report = run_dir / f"{prefix}.report.jsonl"
    evals, attempts = parse(report)
    out = write_json(f"garak/{args.model}.json", {
        "tool": f"garak {version}", "model": args.model, "gguf": Path(gguf).name,
        "decoding": {"temperature": 0.0, "generations": 1, "max_tokens": 256, "stop": []},
        "soft_probe_prompt_cap": args.cap, "probes": PROBES, "attempts": attempts,
        "wall_clock_s": round(wall, 1), **summarize(evals), "evals": evals, "hardware": hardware(),
    })  # fmt: skip
    print(f"garak {version} on {args.model}: {attempts} attempts in {wall:.0f} s -> {out}")


if __name__ == "__main__":
    (RESULTS / "garak").mkdir(parents=True, exist_ok=True)
    main()
