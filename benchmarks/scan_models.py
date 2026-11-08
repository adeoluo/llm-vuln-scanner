"""Full scans of local models and the demo application (the README headline tables).

    uv run python benchmarks/scan_models.py --model qwen3.5-2b
    uv run python benchmarks/scan_models.py --model qwen3.5-4b --probes injection,jailbreak
    uv run python benchmarks/scan_models.py --model demo-vulnerable --backend qwen3.5-2b

Models are the GGUF builds in ``common.MODELS`` served by llama.cpp. Responses are cached
in ../.bench-data/llm-vuln-scanner/cache/<run>.jsonl, so a run can be split into chunks of
probes (each under about 40 minutes on the test machine), interrupted and resumed, and
detectors can be re-evaluated without querying the model again. The generation time of
every chunk that produced new responses is summed in cache/<run>.timing.json, so the
reported wall clock covers the whole scan. Reports go to benchmarks/results/scans/<run>.json.

A scan aborts after 25 consecutive target errors and llama-server output goes to
../.bench-data/llm-vuln-scanner/logs/llama-<run>.log. An early run recorded 539 errors in
540 attempts because llama-server stopped after the first request (the process was gone
and every later request got "connection refused"); without the guard such a run looks
like a model with no findings. A run whose error rate exceeds 1% is written to logs/
instead of benchmarks/results/ and the script exits with status 1.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from common import BENCH, MODELS, PRIMARY, RESULTS, ROOT, hardware, write_json

from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner.engine import ScanAbortedError
from llm_vuln_scanner.probes.base import load_profile
from llm_vuln_scanner.targets import AppTarget, LlamaCppServer


def llama_cpp_version() -> str:
    out = subprocess.run(["llama-server", "--version"], capture_output=True, text=True, check=False)
    return " ".join(line.strip() for line in (out.stdout + out.stderr).splitlines() if "version" in line)


def progress(done: int, total: int) -> None:
    if done % 25 == 0 or done == total:
        print(f"  {done}/{total} {time.strftime('%H:%M:%S')}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="model key, or demo-vulnerable / demo-hardened")
    ap.add_argument(
        "--backend", default=PRIMARY, choices=sorted(MODELS), help="model behind the demo application"
    )
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
            backend = MODELS[args.backend]
            server = stack.enter_context(LlamaCppServer(
                backend.path(), parallel=args.concurrency, ctx_per_slot=backend.ctx_per_slot,
                log_path=str(logs / f"llama-{run}.log"), extra_args=backend.extra_args,
            ))  # fmt: skip
            model_info = {"key": backend.key, "model": backend.model_id, "gguf": backend.gguf_file,
                          "quant": backend.quant, "server_args": list(backend.extra_args)}  # fmt: skip
            port = 18000 + (1 if hardened else 0)
            cmd = [sys.executable, "-m", "llm_vuln_scanner", "demo-app", "--backend", f"openai:{server.base_url}",
                   "--port", str(port)] + (["--hardened"] if hardened else [])  # fmt: skip
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(proc.terminate)
            time.sleep(3)
            cfg.profile = load_profile(ROOT / "examples" / "demo-app.json")
            target = AppTarget(f"http://127.0.0.1:{port}", name=f"{run} (backend {args.backend})")
        else:
            m = MODELS[args.model]
            slots = min(args.concurrency, m.slots)
            srv = stack.enter_context(LlamaCppServer(
                m.path(), parallel=slots, ctx_per_slot=m.ctx_per_slot,
                log_path=str(logs / f"llama-{run}.log"), extra_args=m.extra_args,
            ))  # fmt: skip
            cfg.concurrency = slots
            target = srv.target()
            target.name = run
            model_info = {"key": m.key, "model": m.model_id, "gguf": m.gguf_file, "quant": m.quant,
                          "server_args": list(m.extra_args)}  # fmt: skip
        try:
            report = Scanner(target, cfg, progress=progress).run().to_dict()
        except ScanAbortedError as exc:
            raise SystemExit(f"{run}: {exc}; see {logs}") from exc
    wall = round(time.time() - t0, 1)
    report["hardware"] = hardware()
    report["model"] = model_info
    report["llama_cpp"] = llama_cpp_version()
    report["wall_clock_s"] = wall
    # Sum the time of every chunk that generated responses; a rerun served entirely from
    # the response cache only re-scores and adds nothing.
    timing_path = BENCH / "cache" / f"{run}.timing.json"
    timing = json.loads(timing_path.read_text(encoding="utf-8")) if timing_path.exists() else {"chunks": []}
    cached_after = sum(1 for _ in cache.open(encoding="utf-8")) if cache.exists() else 0
    if cached_after > cached_before:
        timing["chunks"].append({"probes": args.probes, "new_responses": cached_after - cached_before,
                                 "wall_clock_s": wall, "finished": time.strftime("%Y-%m-%dT%H:%M:%S")})  # fmt: skip
        timing_path.write_text(json.dumps(timing, indent=1) + "\n", encoding="utf-8")
    report["generation_wall_clock_s"] = round(sum(c["wall_clock_s"] for c in timing["chunks"]), 1)
    report["generation_chunks"] = timing["chunks"]
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
