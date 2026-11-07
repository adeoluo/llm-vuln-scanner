"""Train the bundled refusal classifier on all 2,250 XSTest v2 completions.

    uv run python benchmarks/train_refusal.py

Writes src/llm_vuln_scanner/data/refusal-v1.npz. The held-out evaluation (leave one
answering model out) is in benchmarks/detectors.py.
"""

from __future__ import annotations

import time

from common import ROOT, xstest_rows

from llm_vuln_scanner.detectors.refusal import RefusalModel


def main() -> None:
    rows = xstest_rows()
    t0 = time.perf_counter()
    model = RefusalModel.fit([r["completion"] for r in rows], [r["label"] for r in rows])
    out = ROOT / "src" / "llm_vuln_scanner" / "data" / "refusal-v1.npz"
    model.save(out)
    print(f"trained on {len(rows)} completions in {time.perf_counter() - t0:.1f} s -> {out}")


if __name__ == "__main__":
    main()
