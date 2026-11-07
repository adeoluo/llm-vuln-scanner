"""Shared helpers for the benchmark scripts (paths, data loading, JSON output)."""

from __future__ import annotations

import contextlib
import csv
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"
BENCH = Path(os.environ.get("LVS_BENCH_DIR", ROOT.parent / ".bench-data" / "llm-vuln-scanner"))
DATA = BENCH / "data"
XSTEST_MODELS = ("gpt4", "llama2new", "llama2orig", "mistralguard", "mistralinstruct")


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


def write_json(name: str, data: Any) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
