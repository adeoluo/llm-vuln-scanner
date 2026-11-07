"""Markdown summary (GitHub step summaries, pull request comments) and workflow
annotations (``::error``/``::warning`` lines GitHub Actions turns into alerts)."""

from __future__ import annotations

from typing import Any

from llm_vuln_scanner.taxonomy import Severity


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"## LLM vulnerability scan: `{report['target']}`",
        "",
        f"{s['vulnerable_probes']} of {s['probes']} probes found a vulnerability; "
        f"{s['successes']} of {s['attempts']} attempts succeeded "
        f"(highest severity: {s['max_severity'] or 'none'}). Duration {report['duration_s']:.1f} s.",
        "",
        "| Severity | Probe | OWASP | ATLAS | Success rate (95% CI) | Attempts |",
        "|---|---|---|---|---|---:|",
    ]
    for f in report["findings"]:
        lo, hi = f["ci95"]
        mark = "**" if f["vulnerable"] else ""
        lines.append(
            f"| {f['severity']} | {mark}{f['probe']}{mark} | {f['owasp']} | {', '.join(f['atlas'])} | "
            f"{_pct(f['rate'])} ({_pct(lo)} to {_pct(hi)}) | {f['attempts']} |"
        )
    lines += ["", "| OWASP category | Tested | Result |", "|---|---|---|"]
    for cid, o in report["owasp"].items():
        result = "vulnerable" if o["vulnerable"] else ("no finding" if o["tested"] else "not tested")
        lines.append(f"| {cid} {o['name']} | {'yes' if o['tested'] else 'no'} | {result} |")
    return "\n".join(lines) + "\n"


def github_annotations(report: dict[str, Any], fail_on: Severity = Severity.HIGH) -> str:
    """One workflow command per vulnerable probe: ``error`` at or above ``fail_on``."""
    out = []
    for f in report["findings"]:
        if not f["vulnerable"]:
            continue
        level = "error" if Severity.parse(f["severity"]) >= fail_on else "warning"
        msg = (f"{f['successes']}/{f['attempts']} attempts succeeded ({f['rate']:.1%}); "
               f"{f['owasp']} {f['owasp_name']}; {', '.join(f['atlas'])}")  # fmt: skip
        title = f"{f['probe']}: {f['title']}".replace(",", " ").replace("::", ":")
        out.append(f"::{level} title={title}::{msg}")
    return "\n".join(out) + ("\n" if out else "")
