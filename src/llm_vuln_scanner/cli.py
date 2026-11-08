"""Command-line interface: ``python -m llm_vuln_scanner <command>``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from llm_vuln_scanner import __version__, _backend
from llm_vuln_scanner import detectors as det
from llm_vuln_scanner import probes as pr
from llm_vuln_scanner.canary import CanaryFactory
from llm_vuln_scanner.engine import ScanAbortedError, ScanConfig, Scanner
from llm_vuln_scanner.probes.base import ProbeContext, load_profile
from llm_vuln_scanner.report import EXTENSIONS, RENDERERS, github_annotations
from llm_vuln_scanner.report.sarif import render_sarif
from llm_vuln_scanner.stats import newcombe_diff
from llm_vuln_scanner.targets import open_target
from llm_vuln_scanner.taxonomy import (
    AGENTIC,
    ATLAS,
    ATLAS_NAME,
    ATLAS_VERSION,
    OWASP,
    OWASP_AGENTIC_NAME,
    OWASP_AGENTIC_VERSION,
    OWASP_LLM_NAME,
    OWASP_LLM_VERSION,
    Severity,
    versions,
)


def _csv(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def _progress(quiet: bool) -> Any:
    if quiet or not sys.stderr.isatty():
        return None

    def show(done: int, total: int) -> None:
        width = 30
        filled = int(width * done / total) if total else width
        sys.stderr.write(f"\r  [{'#' * filled}{'.' * (width - filled)}] {done}/{total}")
        if done == total:
            sys.stderr.write("\n")
        sys.stderr.flush()

    return show


def write_reports(report: dict[str, Any], out: Path, formats: list[str], name: str,
                  sarif_artifact: str) -> list[Path]:  # fmt: skip
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for fmt in formats:
        if fmt not in RENDERERS:
            raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(RENDERERS)}")
        text = render_sarif(report, sarif_artifact) if fmt == "sarif" else RENDERERS[fmt](report)
        path = out / f"{name}.{EXTENSIONS[fmt]}"
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def print_summary(report: dict[str, Any]) -> None:
    s = report["summary"]
    print(f"target {report['target']}: {s['vulnerable_probes']}/{s['probes']} probes vulnerable, "
          f"{s['successes']}/{s['attempts']} attacks succeeded, {report['duration_s']:.1f} s")  # fmt: skip
    print(f"  {'severity':9s} {'probe':30s} {'owasp':10s} {'rate':>7s}  {'95% CI':>15s}  hits")
    for f in report["findings"]:
        lo, hi = f["ci95"]
        mark = "VULN" if f["vulnerable"] else "pass"
        owasp_ref = f.get("owasp_ref", f["owasp"])
        print(f"  {f['severity']:9s} {f['probe']:30s} {owasp_ref:10s} {f['rate']:7.1%}  "
              f"{lo:6.1%} to {hi:6.1%}  {f['successes']}/{f['attempts']} {mark}")  # fmt: skip


def cmd_scan(a: argparse.Namespace) -> int:
    profile = load_profile(a.profile) if a.profile else None
    disabled = tuple(_csv(a.disable)) if a.disable else ()
    extra = ("judge",) if a.judge else ()
    cfg = ScanConfig(
        probes=_csv(a.probes), generations=a.generations, temperature=a.temperature, seed=a.seed,
        concurrency=a.concurrency, max_tokens=a.max_tokens, sample=a.sample,
        cache_path=Path(a.cache) if a.cache else None, data_dir=Path(a.data_dir) if a.data_dir else None,
        profile=profile, extra_detectors=extra, disabled_detectors=disabled,
        max_consecutive_errors=a.max_consecutive_errors or None,
    )  # fmt: skip
    with ExitStack() as stack:
        target = open_target(a.target, stack, api_key_env=a.api_key_env, parallel=a.concurrency)
        judge = open_target(a.judge, stack, parallel=1) if a.judge else None
        try:
            report = Scanner(target, cfg, judge=judge, progress=_progress(a.quiet)).run().to_dict()
        except ScanAbortedError as exc:
            print(f"scan aborted: {exc}", file=sys.stderr)
            return 2
    name = a.name or "scan"
    paths = write_reports(
        report, Path(a.out), _csv(a.format), name, a.sarif_artifact or (a.profile or "llm-app")
    )
    if not a.quiet:
        print_summary(report)
        for p in paths:
            print(f"  wrote {p}")
    if a.github:
        sys.stdout.write(github_annotations(report, Severity.parse(a.fail_on)))
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(RENDERERS["markdown"](report))
    if a.fail_on != "never":
        threshold = Severity.parse(a.fail_on)
        if any(f["vulnerable"] and Severity.parse(f["severity"]) >= threshold for f in report["findings"]):
            return 1
    return 0


def cmd_probes(a: argparse.Namespace) -> int:
    rows = []
    for name in pr.names():
        info = pr.get(name).info
        try:
            n = len(pr.get(name).attempts(ProbeContext(canaries=CanaryFactory(0))))
        except FileNotFoundError:
            n = -1
        rows.append({"name": name, "title": info.title, "owasp": OWASP[info.owasp].ref,
                     "asi": list(info.asi), "atlas": list(info.atlas),
                     "severity": info.severity.name.lower(), "attempts": n,
                     "default": name in pr.DEFAULT_PROBES})  # fmt: skip
    if a.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"{'probe':32s} {'owasp':10s} {'agentic':12s} {'severity':9s} {'attempts':>8s}  atlas")
    for r in rows:
        count = "data" if int(str(r["attempts"])) < 0 else str(r["attempts"])
        atlas = ", ".join(str(x) for x in r["atlas"])  # type: ignore[attr-defined]
        agentic = ",".join(str(x) for x in r["asi"]) or "-"  # type: ignore[attr-defined]
        print(f"{r['name']!s:32s} {r['owasp']!s:10s} {agentic:12s} {r['severity']!s:9s} {count:>8s}  {atlas}")
    return 0


def cmd_detectors(a: argparse.Namespace) -> int:
    for name, desc in det.available().items():
        print(f"{name:20s} {desc}")
    return 0


def cmd_taxonomy(a: argparse.Namespace) -> int:
    infos = [pr.get(n).info for n in pr.names()]
    if a.json:
        print(json.dumps({
            "versions": versions(),
            "owasp_llm": {c.ref: {"name": c.name, "url": c.url, "probes": [i.name for i in infos if i.owasp == k]}
                          for k, c in OWASP.items()},
            "owasp_agentic": {r.ref: {"name": r.name, "probes": [i.name for i in infos if k in i.asi]}
                              for k, r in AGENTIC.items()},
            "atlas": {k: {"name": t.display, "probes": [i.name for i in infos if k in i.atlas]}
                      for k, t in ATLAS.items()},
        }, indent=2))  # fmt: skip
        return 0
    print(f"{OWASP_LLM_NAME} {OWASP_LLM_VERSION}")
    for cat in OWASP.values():
        ps = [i.name for i in infos if i.owasp == cat.id]
        print(f"  {cat.ref:10s} {cat.name:34s} {', '.join(ps) if ps else '(not covered)'}")
    print(f"{OWASP_AGENTIC_NAME} {OWASP_AGENTIC_VERSION}")
    for risk in AGENTIC.values():
        ps = [i.name for i in infos if risk.id in i.asi]
        print(f"  {risk.ref:10s} {risk.name:38s} {', '.join(ps) if ps else '(not covered)'}")
    print(f"{ATLAS_NAME} v{ATLAS_VERSION} techniques")
    for tid, t in ATLAS.items():
        ps = [i.name for i in infos if tid in i.atlas]
        if ps:
            print(f"  {tid:14s} {t.display:56s} {', '.join(ps)}")
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    report = json.loads(Path(a.input).read_text(encoding="utf-8"))
    name = a.name or Path(a.input).stem
    for p in write_reports(report, Path(a.out), _csv(a.format), name, a.sarif_artifact or "llm-app"):
        print(f"wrote {p}")
    return 0


def cmd_compare(a: argparse.Namespace) -> int:
    ra = json.loads(Path(a.a).read_text(encoding="utf-8"))
    rb = json.loads(Path(a.b).read_text(encoding="utf-8"))
    fb = {f["probe"]: f for f in rb["findings"]}
    print(f"{'probe':30s} {'A':>12s} {'B':>12s} {'A - B (95% CI)':>28s}")
    for f in ra["findings"]:
        g = fb.get(f["probe"])
        if g is None or not f["attempts"] or not g["attempts"]:
            continue
        d, lo, hi = newcombe_diff(f["successes"], f["attempts"], g["successes"], g["attempts"])
        print(f"{f['probe']:30s} {f['successes']:>5d}/{f['attempts']:<6d} {g['successes']:>5d}/{g['attempts']:<6d}"
              f" {d:+8.1%} ({lo:+.1%} to {hi:+.1%})")  # fmt: skip
    return 0


def cmd_demo_app(a: argparse.Namespace) -> int:
    from llm_vuln_scanner.demo_app import DemoApp, DemoConfig, serve

    with ExitStack() as stack:
        backend = open_target(a.backend, stack, parallel=a.parallel)
        app = DemoApp(backend, DemoConfig(hardened=a.hardened))
        server = serve(app, a.host, a.port)
        mode = "hardened" if a.hardened else "VULNERABLE"
        print(
            f"demo app ({mode}, backend {backend.name}) on http://{a.host}:{server.server_port}", flush=True
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    from llm_vuln_scanner.service import serve

    server = serve(a.host, a.port, tuple(_csv(a.allow_target)))
    print(f"llm-vuln-scanner service on http://{a.host}:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def cmd_info(a: argparse.Namespace) -> int:
    print(json.dumps({"version": __version__, "rust_core": _backend.rust_available(),
                      "probes": len(pr.names()), "detectors": len(det.available()),
                      "taxonomy": versions()}, indent=2))  # fmt: skip
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm-vuln-scanner", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a target and write reports")
    s.add_argument("--target", required=True, help="naive, refusing, openai:URL[#MODEL], llamacpp:PATH, "
                   "transformers:MODEL_ID or app:URL")  # fmt: skip
    s.add_argument("--probes", default="default", help="comma list of probes, families, 'default' or 'all'")
    s.add_argument("--generations", type=int, default=1, help="responses per attempt (seed + g)")
    s.add_argument("--temperature", type=float, default=0.0)
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--concurrency", type=int, default=1, help="parallel requests (and llama.cpp slots)")
    s.add_argument("--max-tokens", type=int, default=None, help="override every attempt's token budget")
    s.add_argument("--sample", type=int, default=None, help="at most N attempts per probe (seeded)")
    s.add_argument("--cache", default=None, help="JSONL response cache (resumable scans)")
    s.add_argument("--max-consecutive-errors", type=int, default=25,
                   help="abort when the target fails this many times in a row (0 never aborts)")  # fmt: skip
    s.add_argument("--data-dir", default=None, help="prepared datasets for dataset.* probes")
    s.add_argument("--profile", default=None, help="application profile JSON (app targets)")
    s.add_argument("--judge", default=None, help="target spec of an LLM judge (adds the judge detector)")
    s.add_argument("--disable", default=None, help="comma list of detectors to turn off")
    s.add_argument("--api-key-env", default=None, help="environment variable holding the API key")
    s.add_argument("--out", default="reports", help="output directory")
    s.add_argument("--name", default=None, help="report file name stem (default 'scan')")
    s.add_argument("--format", default="json,html,sarif,junit,markdown", help="comma list of formats")
    s.add_argument("--sarif-artifact", default=None, help="file SARIF results point at")
    s.add_argument("--fail-on", default="never",
                   help="exit 1 if a finding at or above this severity (low..critical) or 'never'")  # fmt: skip
    s.add_argument("--github", action="store_true", help="emit workflow annotations and a step summary")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    sp = sub.add_parser("probes", help="list probes")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_probes)
    sub.add_parser("detectors", help="list detectors").set_defaults(func=cmd_detectors)
    t = sub.add_parser("taxonomy", help="OWASP LLM 2026, OWASP Agentic 2026 and ATLAS v2026.10 coverage")
    t.add_argument("--json", action="store_true", help="machine-readable output")
    t.set_defaults(func=cmd_taxonomy)
    sub.add_parser("info", help="version and build details").set_defaults(func=cmd_info)

    r = sub.add_parser("report", help="re-render a JSON report in other formats")
    r.add_argument("input")
    r.add_argument("--out", default="reports")
    r.add_argument("--name", default=None)
    r.add_argument("--format", default="html,sarif,junit,markdown")
    r.add_argument("--sarif-artifact", default=None)
    r.set_defaults(func=cmd_report)

    c = sub.add_parser("compare", help="compare success rates of two JSON reports")
    c.add_argument("a")
    c.add_argument("b")
    c.set_defaults(func=cmd_compare)

    d = sub.add_parser("demo-app", help="run the deliberately vulnerable demo application")
    d.add_argument("--backend", default="naive", help="target spec of the model behind the app")
    d.add_argument("--hardened", action="store_true")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8088)
    d.add_argument("--parallel", type=int, default=4)
    d.set_defaults(func=cmd_demo_app)

    v = sub.add_parser("serve", help="run the scanner HTTP service")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.add_argument("--allow-target", default="naive,refusing", help="comma list of allowed target prefixes")
    v.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
