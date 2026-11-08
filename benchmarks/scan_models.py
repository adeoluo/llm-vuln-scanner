"""Full scans of local models and the demo application (the README headline tables).

    uv run python benchmarks/scan_models.py --model qwen2.5-1.5b
    uv run python benchmarks/scan_models.py --model demo-vulnerable --backend qwen2.5-1.5b

Responses are cached in ../.bench-data/llm-vuln-scanner/cache/<run>.jsonl, so a run can
be interrupted and resumed, and detectors can be re-evaluated without querying the
model again. Reports go to benchmarks/results/scans/<run>.json.

A scan aborts after 25 consecutive target errors and llama-server output goes to
../.bench-data/llm-vuln-scanner/logs/llama-<run>.log. A first SmolLM2 run recorded 539
errors in 540 attempts because llama-server stopped after the first request (the process
was gone and every later request got "connection refused"); without the guard such a run
looks like a model with no findings. A run whose error rate exceeds 1% is written to
logs/ instead of benchmarks/results/ and the script exits with status 1.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from common import BENCH, RESULTS, ROOT, hardware, write_json

from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner.engine import ScanAbortedError
from llm_vuln_scanner.probes.base import load_profile
from llm_vuln_scanner.targets import AppTarget, LlamaCppServer

HF = Path(os.environ.get("HF_HUB_CACHE", Path.home() / ".cache" / "huggingface" / "hub"))
MODELS = {
    "qwen2.5-1.5b": "llamacpp:models--Qwen--Qwen2.5-1.5B-Instruct-GGUF/*/qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "smollm2-1.7b": "llamacpp:models--HuggingFaceTB--SmolLM2-1.7B-Instruct-GGUF/*/smollm2-1.7b-instruct-q4_k_m.gguf",
    "qwen2.5-0.5b": "transformers:Qwen/Qwen2.5-0.5B-Instruct",
    # Q3_K_M (1.7 GB) rather than Q4_K_M (2.1 GB) keeps the server under 2.5 GB of memory.
    "qwen2.5-3b": "llamacpp:models--Qwen--Qwen2.5-3B-Instruct-GGUF/*/qwen2.5-3b-instruct-q3_k_m.gguf",
}
# llama.cpp KV cache per slot: SmolLM2-1.7B has no grouped-query attention (32 KV heads of
# 64 dims in 24 layers), so 4 slots x 4,096 tokens would need 3.2 GB of f16 KV cache on an
# 8 GB machine; 2 slots x 2,048 tokens need 0.8 GB. Qwen2.5 uses 2 KV heads (GQA).
CTX = {"smollm2-1.7b": 2048}
SLOTS = {"smollm2-1.7b": 2, "qwen2.5-3b": 2}


def resolve(name: str) -> str:
    spec = MODELS[name]
    kind, _, rest = spec.partition(":")
    if kind == "llamacpp":
        hits = glob.glob(str(HF / rest.replace("/*/", "/snapshots/*/")))
        if not hits:
            raise SystemExit(f"{name}: GGUF not found under {HF}; run scripts/download_models.sh")
        return f"llamacpp:{hits[0]}"
    return spec


def progress(done: int, total: int) -> None:
    if done % 25 == 0 or done == total:
        print(f"  {done}/{total} {time.strftime('%H:%M:%S')}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="model key, or demo-vulnerable / demo-hardened")
    ap.add_argument("--backend", default="qwen2.5-1.5b", help="model behind the demo application")
    ap.add_argument("--probes", default="default")
    ap.add_argument("--sample", type=int, default=None)
    ap.add_argument("--generations", type=int, default=1)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--run", default=None, help="run name (default: model name)")
    ap.add_argument("--data-dir", default=str(BENCH / "data"))
    args = ap.parse_args()
    run = args.run or args.model
    cache = BENCH / "cache" / f"{run}.jsonl"
    cfg = ScanConfig(
        probes=[p for p in args.probes.split(",") if p], generations=args.generations,
        temperature=args.temperature, seed=args.seed, concurrency=args.concurrency, sample=args.sample,
        cache_path=cache, data_dir=Path(args.data_dir), max_consecutive_errors=25,
    )  # fmt: skip
    logs = BENCH / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    cached_before = sum(1 for _ in cache.open(encoding="utf-8")) if cache.exists() else 0
    t0 = time.time()
    with ExitStack() as stack:
        if args.model.startswith("demo-"):
            hardened = args.model == "demo-hardened"
            backend_spec = resolve(args.backend)
            server = stack.enter_context(LlamaCppServer(
                backend_spec.split(":", 1)[1], parallel=args.concurrency,
                log_path=str(logs / f"llama-{run}.log"),
            ))  # fmt: skip
            port = 18000 + (1 if hardened else 0)
            cmd = [sys.executable, "-m", "llm_vuln_scanner", "demo-app", "--backend", f"openai:{server.base_url}",
                   "--port", str(port)] + (["--hardened"] if hardened else [])  # fmt: skip
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(proc.terminate)
            time.sleep(3)
            cfg.profile = load_profile(ROOT / "examples" / "demo-app.json")
            target = AppTarget(f"http://127.0.0.1:{port}", name=f"{run} (backend {args.backend})")
        else:
            kind, _, rest = resolve(args.model).partition(":")
            if kind == "llamacpp":
                slots = min(args.concurrency, SLOTS.get(args.model, args.concurrency))
                srv = stack.enter_context(LlamaCppServer(
                    rest, parallel=slots, ctx_per_slot=CTX.get(args.model, 4096),
                    log_path=str(logs / f"llama-{run}.log"),
                ))  # fmt: skip
                cfg.concurrency = slots
                target = srv.target()
            else:
                from llm_vuln_scanner.targets.transformers_target import TransformersTarget

                target = TransformersTarget(rest)
            target.name = run
        try:
            report = Scanner(target, cfg, progress=progress).run().to_dict()
        except ScanAbortedError as exc:
            raise SystemExit(f"{run}: {exc}; see {logs}") from exc
    report["hardware"] = hardware()
    report["wall_clock_s"] = round(time.time() - t0, 1)
    # A rerun served from the response cache only re-scores; keep the generation time.
    previous = RESULTS / "scans" / f"{run}.json"
    if cached_before >= len(report["attempts"]) and previous.exists():
        old = json.loads(previous.read_text(encoding="utf-8"))
        report["generation_wall_clock_s"] = old.get("generation_wall_clock_s", old.get("wall_clock_s"))
        report["rescored_from_cache"] = True
    else:
        report["generation_wall_clock_s"] = report["wall_clock_s"]
    s = report["summary"]
    total = s["attempts"] + s["errors"]
    if s["errors"] > 0.01 * total:
        out = logs / f"failed-{run}.json"
        out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        raise SystemExit(f"{run}: {s['errors']}/{total} attempts errored; report kept at {out}")
    out = write_json(f"scans/{run}.json", report)
    print(f"{run}: {s['successes']}/{s['attempts']} succeeded, {s['errors']} errors -> {out}")


if __name__ == "__main__":
    (RESULTS / "scans").mkdir(parents=True, exist_ok=True)
    main()
