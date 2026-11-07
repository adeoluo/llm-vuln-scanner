"""Shared helpers for the benchmark scripts (paths, data loading, JSON output)."""

from __future__ import annotations

import contextlib
import csv
import json
import os
import platform
import re
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


_AWS_ID = re.compile(r"\b(AKIA|ASIA)[A-Z2-7]{16}\b")
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9+/])(?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[A-Z])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])")


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
    path.write_text(json.dumps(mask_credentials(data), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
