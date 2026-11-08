"""Print the README result tables from benchmarks/results/ (Markdown).

uv run --no-sync python benchmarks/report.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from common import MODELS as LOCAL_MODELS
from common import PRIMARY, RESULTS

from llm_vuln_scanner.report import upgrade_report

MODELS = list(LOCAL_MODELS)
APPS = ["demo-vulnerable", "demo-hardened"]
OWASP_ORDER = [f"LLM{i:02d}" for i in range(1, 11)]


def load(name: str) -> dict[str, Any] | None:
    p = RESULTS / name
    if not p.exists():
        return None
    data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
    # A scan split into chunks of probes writes partial reports until its final full run.
    expected = ["dataset"] if "datasets" in name else ["default"]
    if (
        name.startswith("scans/")
        and not name.startswith("scans/demo-")
        and data["config"]["probes"] != expected
    ):
        return None
    # Scan reports always print with the current taxonomy (OWASP 2026, ATLAS v2026.10).
    return upgrade_report(data) if name.startswith("scans/") else data


def cell(f: dict[str, Any] | None) -> str:
    if f is None:
        return "not run"
    if not f["attempts"]:
        return "n/a"
    lo, hi = f["ci95"]
    return f"{f['successes']}/{f['attempts']} ({f['rate']:.0%}, {lo:.0%} to {hi:.0%})"


def scans_table(runs: list[str], title: str, wall_clock: bool = True) -> None:
    reports = {r: load(f"scans/{r}.json") for r in runs}
    reports = {r: v for r, v in reports.items() if v is not None}
    if not reports:
        return
    probes: list[tuple[str, str]] = []
    for rep in reports.values():
        for f in rep["findings"]:
            if (f["probe"], f["owasp_ref"]) not in probes:
                probes.append((f["probe"], f["owasp_ref"]))
    probes.sort(key=lambda p: (p[1], p[0]))
    print(f"\n#### {title}\n")
    print("| Probe | OWASP 2026 | " + " | ".join(reports) + " |")
    print("|---|---|" + "---|" * len(reports))
    by = {r: {f["probe"]: f for f in rep["findings"]} for r, rep in reports.items()}
    for probe, owasp in probes:
        print(f"| `{probe}` | {owasp} | " + " | ".join(cell(by[r].get(probe)) for r in reports) + " |")
    totals = []
    for rep in reports.values():
        s = rep["summary"]
        totals.append(f"**{s['successes']}/{s['attempts']}** ({s['successes'] / max(1, s['attempts']):.0%})")
    print("| **All attacks** | | " + " | ".join(totals) + " |")
    print("| Errors | | " + " | ".join(str(rep["summary"]["errors"]) for rep in reports.values()) + " |")
    if wall_clock:
        print(
            "| Wall clock | | "
            + " | ".join(
                f"{rep.get('generation_wall_clock_s', rep['duration_s']) / 60:.0f} min"
                for rep in reports.values()
            )
            + " |"
        )


def models_table() -> None:
    rows = [(k, load(f"scans/{k}.json")) for k in MODELS]
    rows = [(k, r) for k, r in rows if r is not None]
    if not rows:
        return
    print("\n#### Models scanned (llama.cpp, greedy, 4 parallel slots of 4,096 tokens)\n")
    print("| Key | Model | Released | GGUF build | Quantization | Mean output tokens | Scan time |")
    print("|---|---|---|---|---|---|---|")
    for k, r in rows:
        m = LOCAL_MODELS[k]
        toks = [a["completion_tokens"] or 0 for a in r["attempts"]]
        print(f"| {k} | [{m.model_id}](https://huggingface.co/{m.model_id}) | {m.released} | "
              f"[{m.gguf_repo}](https://huggingface.co/{m.gguf_repo}) `{m.gguf_file}` | {m.quant} | "
              f"{sum(toks) / max(1, len(toks)):.0f} | {r.get('generation_wall_clock_s', 0) / 60:.0f} min |")  # fmt: skip
    version = rows[0][1].get("llama_cpp", "").replace("version: ", "")
    print(f"\nServer: llama.cpp `llama-server` {version}.")


def detectors_table() -> None:
    d = load("detectors.json")
    if d is None:
        return
    print(f"\n#### Refusal detectors on XSTest v2 ({d['n']:,} human-labelled completions)\n")
    print("| Detector | Accuracy | Precision | Recall | F1 | Time |")
    print("|---|---|---|---|---|---|")
    for name, m in d["detectors"].items():

        def ci(k: str, m: dict[str, Any] = m) -> str:
            lo, hi = m[k + "_ci95"]
            return f"{m[k]:.3f} ({lo:.3f} to {hi:.3f})"

        print(
            f"| {name} | {ci('accuracy')} | {ci('precision')} | {ci('recall')} | {ci('f1')} | {m['seconds']:.1f} s |"
        )


def speed_table() -> None:
    s = load("speed.json")
    if s is None:
        return
    print(
        f"\n#### Detector kernels, Rust core versus Python reference ({s['texts']:,} texts, median of {s['repeats']})\n"
    )
    print("| Kernel | Python (texts/s) | Rust (texts/s) | Speedup |")
    print("|---|---|---|---|")
    for k in s["kernels"]:
        extra = f" (stdlib `re`: {k['stdlib_re_per_s']:,.0f}/s)" if "stdlib_re_per_s" in k else ""
        print(
            f"| {k['kernel']}{extra} | {k['python_per_s']:,.0f} | {k['rust_per_s']:,.0f} | {k['speedup']:.1f}x |"
        )
    print("\n| LCS, 200-token secret versus | Python | Rust | Speedup |")
    print("|---|---|---|---|")
    for r in s["lcs_scaling"]:
        print(
            f"| {r['output_tokens']:,} tokens | {r['python_s'] * 1e3:,.1f} ms | {r['rust_s'] * 1e3:,.3f} ms | {r['speedup']:,.0f}x |"
        )


def garak_table(model: str = PRIMARY) -> None:
    g = load(f"garak/{model}.json")
    ours = load(f"scans/{model}.json")
    if g is None or ours is None:
        return
    print(f"\n#### Same model ({model}), garak versus this scanner, by OWASP category\n")
    print(
        "| OWASP | garak probes | garak attacks flagged | this scanner probes | this scanner attacks succeeded |"
    )
    print("|---|---|---|---|---|")
    for o in OWASP_ORDER:
        go = g["per_owasp"].get(o)
        oo = ours["owasp"].get(o, {})
        if not go and not oo.get("tested"):
            continue
        gs = f"{go['fails']}/{go['total']} ({go['fails'] / max(1, go['total']):.0%})" if go else "not covered"
        os_ = f"{oo['successes']}/{oo['attempts']} ({oo['rate']:.0%})" if oo.get("tested") else "not covered"
        print(
            f"| {o} {oo.get('name', '')} | {go['probes'] if go else 0} | {gs} | {len(oo.get('probes', []))} | {os_} |"
        )
    print(f"\ngarak: {g['attempts']} attempts in {g['wall_clock_s'] / 60:.0f} min; this scanner: "
          f"{ours['summary']['attempts']} attempts in {ours.get('generation_wall_clock_s', 0) / 60:.0f} min.")  # fmt: skip


def owasp_table(runs: list[str]) -> None:
    reports = {r: load(f"scans/{r}.json") for r in runs}
    reports = {r: v for r, v in reports.items() if v is not None}
    if not reports:
        return
    print("\n#### OWASP Top 10 for LLM Applications 2026: coverage and attack success rate\n")
    print("| Category | " + " | ".join(reports) + " |")
    print("|---|" + "---|" * len(reports))
    first = next(iter(reports.values()))
    for o in OWASP_ORDER:
        row = []
        for rep in reports.values():
            c = rep["owasp"][o]
            row.append(f"{c['successes']}/{c['attempts']} ({c['rate']:.0%})" if c["tested"] else "not tested")
        print(f"| {o}:2026 {first['owasp'][o]['name']} | " + " | ".join(row) + " |")
    print("\n#### OWASP Top 10 for Agentic Applications 2026: risks the agent and tool probes exercise\n")
    print("| Risk | Probes | " + " | ".join(reports) + " |")
    print("|---|---|" + "---|" * len(reports))
    for rid, risk in first["agentic"].items():
        if not risk["tested"]:
            continue
        row = []
        for rep in reports.values():
            c = rep["agentic"][rid]
            row.append(f"{c['successes']}/{c['attempts']} ({c['rate']:.0%})" if c["tested"] else "not tested")
        probes = ", ".join(f"`{p}`" for p in risk["probes"])
        print(f"| {rid}:2026 {risk['name']} | {probes} | " + " | ".join(row) + " |")


def ablation_table() -> None:
    a = load("ablations.json")
    if a is None:
        return
    runs = a["runs"]
    print("\n#### Detector ablations (re-scored offline on the stored responses)\n")
    print("| Variant | " + " | ".join(r["run"] for r in runs) + " |")
    print("|---|" + "---|" * len(runs))
    names = list(runs[0]["variants"])
    for name in names:
        cells = []
        for r in runs:
            t = r["variants"].get(name)
            cells.append(
                "n/a" if t is None else f"{t['successes']}/{t['attempts']} (+{t['gained']}, -{t['lost']})"
            )
        print(f"| {name} | " + " | ".join(cells) + " |")


def main() -> None:
    models_table()
    scans_table(MODELS, "Local models, default probe set (540 attempts each, greedy)", wall_clock=False)
    owasp_table(MODELS + APPS)
    label = LOCAL_MODELS[PRIMARY].label
    scans_table(
        APPS, f"Demo application, vulnerable versus hardened (same {label} backend)", wall_clock=False
    )
    scans_table([f"{PRIMARY}-datasets"], f"Public attack datasets on {label}", wall_clock=False)
    ablation_table()
    detectors_table()
    speed_table()
    garak_table()
    print()


if __name__ == "__main__":
    Path(RESULTS).mkdir(parents=True, exist_ok=True)
    main()
