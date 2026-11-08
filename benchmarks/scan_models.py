"""Full scans of local models and the demo application (the README headline tables).

    uv run python benchmarks/scan_models.py --model qwen2.5-1.5b
    uv run python benchmarks/scan_models.py --model demo-vulnerable --backend qwen2.5-1.5b

Responses are cached in ../.bench-data/llm-vuln-scanner/cache/<run>.jsonl, so a run can
be interrupted and resumed, and detectors can be re-evaluated without querying the
model again (``--rescore``). Reports go to benchmarks/results/scans/<run>.json.
"""

from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from common import BENCH, RESULTS, ROOT, hardware, write_json

from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner.probes.base import load_profile
from llm_vuln_scanner.targets import AppTarget, LlamaCppServer, open_target

HF = Path(os.environ.get("HF_HUB_CACHE", Path.home() / ".cache" / "huggingface" / "hub"))
MODELS = {
    "qwen2.5-1.5b": "llamacpp:models--Qwen--Qwen2.5-1.5B-Instruct-GGUF/*/qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "smollm2-1.7b": "llamacpp:models--HuggingFaceTB--SmolLM2-1.7B-Instruct-GGUF/*/smollm2-1.7b-instruct-q4_k_m.gguf",
    "qwen2.5-0.5b": "transformers:Qwen/Qwen2.5-0.5B-Instruct",
}


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
        cache_path=cache, data_dir=Path(args.data_dir),
    )  # fmt: skip
    t0 = time.time()
    with ExitStack() as stack:
        if args.model.startswith("demo-"):
            hardened = args.model == "demo-hardened"
            backend_spec = resolve(args.backend)
            server = stack.enter_context(
                LlamaCppServer(backend_spec.split(":", 1)[1], parallel=args.concurrency)
            )
            port = 18000 + (1 if hardened else 0)
            cmd = [sys.executable, "-m", "llm_vuln_scanner", "demo-app", "--backend", f"openai:{server.base_url}",
                   "--port", str(port)] + (["--hardened"] if hardened else [])  # fmt: skip
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(proc.terminate)
            time.sleep(3)
            cfg.profile = load_profile(ROOT / "examples" / "demo-app.json")
            target = AppTarget(f"http://127.0.0.1:{port}", name=f"{run} (backend {args.backend})")
        else:
            target = open_target(resolve(args.model), stack, parallel=args.concurrency)
            target.name = run
        report = Scanner(target, cfg, progress=progress).run().to_dict()
    report["hardware"] = hardware()
    report["wall_clock_s"] = round(time.time() - t0, 1)
    out = write_json(f"scans/{run}.json", report)
    s = report["summary"]
    print(f"{run}: {s['successes']}/{s['attempts']} succeeded, {s['errors']} errors -> {out}")


if __name__ == "__main__":
    (RESULTS / "scans").mkdir(parents=True, exist_ok=True)
    main()
