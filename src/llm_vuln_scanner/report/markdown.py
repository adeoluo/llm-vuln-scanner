"""Markdown summary (GitHub step summaries, pull request comments) and workflow
annotations (``::error``/``::warning`` lines GitHub Actions turns into alerts)."""

from __future__ import annotations

from typing import Any

from llm_vuln_scanner.report.taxonomy import upgrade_report
from llm_vuln_scanner.taxonomy import Severity


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def _coverage(title: str, table: dict[str, Any]) -> list[str]:
    lines = ["", f"| {title} | Tested | Result |", "|---|---|---|"]
    for cid, o in table.items():
        result = "vulnerable" if o["vulnerable"] else ("no finding" if o["tested"] else "not tested")
        lines.append(f"| {o.get('ref', cid)} {o['name']} | {'yes' if o['tested'] else 'no'} | {result} |")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    report = upgrade_report(report)
    s = report["summary"]
    tax = report["taxonomy"]
    lines = [
        f"## LLM vulnerability scan: `{report['target']}`",
        "",
        f"{s['vulnerable_probes']} of {s['probes']} probes found a vulnerability; "
        f"{s['successes']} of {s['attempts']} attempts succeeded "
        f"(highest severity: {s['max_severity'] or 'none'}). Duration {report['duration_s']:.1f} s.",
        "",
        f"| Severity | Probe | OWASP LLM {tax['owasp_llm']} | OWASP Agentic {tax['owasp_agentic']} | "
        f"ATLAS v{tax['atlas']} | Success rate (95% CI) | Attempts |",
        "|---|---|---|---|---|---|---:|",
    ]
    for f in report["findings"]:
        lo, hi = f["ci95"]
        mark = "**" if f["vulnerable"] else ""
        lines.append(
            f"| {f['severity']} | {mark}{f['probe']}{mark} | {f['owasp_ref']} | {', '.join(f['asi']) or 'none'} | "
            f"{', '.join(f['atlas'])} | "
            f"{_pct(f['rate'])} ({_pct(lo)} to {_pct(hi)}) | {f['attempts']} |"
        )
    lines += _coverage(f"OWASP Top 10 for LLM Applications {tax['owasp_llm']}", report["owasp"])
    lines += _coverage(f"OWASP Top 10 for Agentic Applications {tax['owasp_agentic']}", report["agentic"])
    return "\n".join(lines) + "\n"


def github_annotations(report: dict[str, Any], fail_on: Severity = Severity.HIGH) -> str:
    """One workflow command per vulnerable probe: ``error`` at or above ``fail_on``."""
    out = []
    report = upgrade_report(report)
    for f in report["findings"]:
        if not f["vulnerable"]:
            continue
        level = "error" if Severity.parse(f["severity"]) >= fail_on else "warning"
        agentic = f"; {', '.join(f['asi'])}" if f["asi"] else ""
        msg = (f"{f['successes']}/{f['attempts']} attempts succeeded ({f['rate']:.1%}); "
               f"{f['owasp_ref']} {f['owasp_name']}{agentic}; {', '.join(f['atlas'])}")  # fmt: skip
        title = f"{f['probe']}: {f['title']}".replace(",", " ").replace("::", ":")
        out.append(f"::{level} title={title}::{msg}")
    return "\n".join(out) + ("\n" if out else "")
