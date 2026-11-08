"""Re-score committed scans offline from the response cache, after a detector change.

    uv run --no-sync python benchmarks/rescore.py                    # every committed scan
    uv run --no-sync python benchmarks/rescore.py qwen3.5-2b demo-vulnerable

Rebuilds each scan with the configuration stored in its report (probes, seed, sample,
profile, data directory) against a target that only answers from
../.bench-data/llm-vuln-scanner/cache/<run>.jsonl, so no model is loaded and a missing
response is an error instead of a new generation. The model, server and timing fields
of the original report are kept; detections, findings and summaries are recomputed.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from common import BENCH, RESULTS, ROOT, write_json

from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner.probes.base import load_profile
from llm_vuln_scanner.targets.base import CallableTarget
from llm_vuln_scanner.types import Attempt

KEEP = ("hardware", "model", "llama_cpp", "started_at", "duration_s", "wall_clock_s",
        "generation_wall_clock_s", "generation_chunks")  # fmt: skip


def cache_only(name: str) -> CallableTarget:
    def miss(attempt: Attempt) -> str:
        raise RuntimeError(f"{attempt.id} is not in the response cache")

    target = CallableTarget(miss)
    target.name = name
    return target


def rescore(run: str) -> dict[str, Any]:
    path = RESULTS / "scans" / f"{run}.json"
    old = json.loads(path.read_text(encoding="utf-8"))
    c = old["config"]
    cfg = ScanConfig(
        probes=c["probes"], generations=c["generations"], temperature=c["temperature"], seed=c["seed"],
        max_tokens=c["max_tokens"], sample=c["sample"], only=c.get("only"),
        cache_path=BENCH / "cache" / f"{run}.jsonl", data_dir=BENCH / "data",
        profile=load_profile(ROOT / "examples" / "demo-app.json") if c.get("profile") else None,
        extra_detectors=tuple(c["extra_detectors"]), disabled_detectors=tuple(c["disabled_detectors"]),
    )  # fmt: skip
    new = Scanner(cache_only(old["target"]), cfg).run().to_dict()
    if new["summary"]["errors"]:
        raise SystemExit(f"{run}: {new['summary']['errors']} attempts are missing from the cache")
    for key in KEEP:
        if key in old:
            new[key] = old[key]
    new["rescored"] = "offline from the response cache after a detector change"
    write_json(f"scans/{run}.json", new)
    return new


def main() -> None:
    runs = sys.argv[1:] or sorted(p.stem for p in (RESULTS / "scans").glob("*.json"))
    for run in runs:
        before = json.loads((RESULTS / "scans" / f"{run}.json").read_text(encoding="utf-8"))["summary"]
        after = rescore(run)["summary"]
        print(f"{run:24s} {before['successes']:4d} -> {after['successes']:4d} of {after['attempts']}")


if __name__ == "__main__":
    main()
