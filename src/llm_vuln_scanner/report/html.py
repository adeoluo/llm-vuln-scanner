"""Self-contained HTML report (no external assets, every value HTML-escaped).

The report is a scanner output that embeds attacker-chosen strings (prompts, model
responses, evidence), so it must not itself be an XSS sink: every dynamic value passes
through :func:`html.escape`, and the page carries a Content-Security-Policy that forbids
scripts. ``tests/test_reports.py`` renders a report whose responses contain script
payloads and checks that the active-content detector finds nothing in the output.
"""

from __future__ import annotations

from html import escape
from typing import Any

_CSS = """
body{font:14px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;margin:24px;color:#1E293B;
background:#F8FAFC}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.muted{color:#64748B}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:#fff;border:1px solid #E2E8F0;border-radius:8px;padding:10px 14px;min-width:120px}
.card b{display:block;font-size:20px}table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #E2E8F0;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#F1F5F9}td.num{text-align:right;font-variant-numeric:tabular-nums}
.sev{border-radius:4px;padding:1px 6px;color:#fff;font-size:12px}
.critical{background:#7F1D1D}.high{background:#DC2626}.medium{background:#D97706}
.low{background:#2563EB}.info{background:#64748B}.ok{color:#047857}.bad{color:#B91C1C;font-weight:600}
.bar{position:relative;height:10px;background:#E2E8F0;border-radius:5px;min-width:120px}
.bar span{position:absolute;top:0;height:10px;background:#6366F1;border-radius:5px}
.bar i{position:absolute;top:-2px;height:14px;border-left:2px solid #1E293B}
details{background:#fff;border:1px solid #E2E8F0;border-radius:8px;margin:8px 0;padding:8px 12px}
summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;background:#F1F5F9;padding:8px;
border-radius:6px;font-size:12px}
"""


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def _bar(rate: float, lo: float, hi: float) -> str:
    return (f'<div class="bar"><span style="left:{lo * 100:.1f}%;width:{max(0.5, (hi - lo) * 100):.1f}%">'
            f'</span><i style="left:{rate * 100:.1f}%"></i></div>')  # fmt: skip


def render_html(report: dict[str, Any]) -> str:
    e = escape
    s = report["summary"]
    rows = []
    for f in report["findings"]:
        lo, hi = f["ci95"]
        status = '<span class="bad">vulnerable</span>' if f["vulnerable"] else '<span class="ok">pass</span>'
        rows.append(
            f"<tr><td><span class='sev {e(f['severity'])}'>{e(f['severity'])}</span></td>"
            f"<td><a href='#{e(f['probe'])}'>{e(f['probe'])}</a><br><span class='muted'>{e(f['title'])}"
            f"</span></td><td>{e(f['owasp'])}</td><td>{e(', '.join(f['atlas']))}</td><td>{status}</td>"
            f"<td class='num'>{f['successes']}/{f['attempts']}</td><td class='num'>{_pct(f['rate'])}<br>"
            f"<span class='muted'>{_pct(lo)} to {_pct(hi)}</span></td><td>{_bar(f['rate'], lo, hi)}</td></tr>"
        )
    owasp_rows = []
    for cid, o in report["owasp"].items():
        result = ('<span class="bad">vulnerable</span>' if o["vulnerable"] else
                  ('<span class="ok">no finding</span>' if o["tested"] else '<span class="muted">not tested</span>'))  # fmt: skip
        owasp_rows.append(
            f"<tr><td>{e(cid)}</td><td><a href='{e(o['url'])}'>{e(o['name'])}</a></td>"
            f"<td>{e(', '.join(o['probes']) or '-')}</td><td class='num'>{o['successes']}/{o['attempts']}"
            f"</td><td>{result}</td></tr>"
        )
    details = []
    for f in report["findings"]:
        parts = [f"<details id='{e(f['probe'])}'{' open' if f['vulnerable'] else ''}>",
                 f"<summary>{e(f['probe'])}: {e(f['title'])} ({f['successes']}/{f['attempts']})</summary>",
                 f"<p>{e(f['description'])}</p><p><b>Remediation.</b> {e(f['remediation'])}</p>"]  # fmt: skip
        hits = ", ".join(f"{e(k)} {v}" for k, v in f["detector_hits"].items())
        parts.append(f"<p class='muted'>Detector hits: {hits or 'none'}</p>")
        for key, cells in f["breakdown"].items():
            if len(cells) < 2:
                continue
            cs = "".join(
                f"<tr><td>{e(v)}</td><td class='num'>{k}/{n}</td></tr>" for v, (k, n) in cells.items()
            )
            parts.append(f"<table style='width:auto;display:inline-table;margin:4px 8px 4px 0'>"
                         f"<tr><th>{e(key)}</th><th>succeeded</th></tr>{cs}</table>")  # fmt: skip
        for ex in f["examples"]:
            parts.append(
                f"<p><b>{e(ex['attempt'])}</b> (generation {ex['generation']})</p>"
                f"<pre>Prompt: {e(ex['prompt'])}\n\nResponse: {e(ex['response'])}\n\n"
                f"Evidence: {e('; '.join(ex['evidence']))}</pre>"
            )
        if f["references"]:
            refs = " ".join(f"<a href='{e(r)}'>{e(r)}</a>" for r in f["references"])
            parts.append(f"<p class='muted'>References: {refs}</p>")
        parts.append("</details>")
        details.append("".join(parts))
    cfg = report["config"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM vulnerability scan: {e(report["target"])}</title><style>{_CSS}</style></head><body>
<h1>LLM vulnerability scan</h1>
<div class="muted">Target <b>{e(report["target"])}</b>, started {e(report["started_at"])},
{report["duration_s"]:.1f} s, llm-vuln-scanner {e(report["tool"]["version"])},
seed {e(str(cfg["seed"]))}, generations {e(str(cfg["generations"]))},
temperature {e(str(cfg["temperature"]))}</div>
<div class="cards">
<div class="card"><b>{s["vulnerable_probes"]}/{s["probes"]}</b>probes vulnerable</div>
<div class="card"><b>{s["successes"]}/{s["attempts"]}</b>attacks succeeded</div>
<div class="card"><b>{e(s["max_severity"] or "none")}</b>highest severity</div>
<div class="card"><b>{s["errors"]}</b>target errors</div>
</div>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Probe</th><th>OWASP</th><th>ATLAS</th><th>Status</th><th>Succeeded</th>
<th>Rate (95% CI)</th><th></th></tr>{"".join(rows)}</table>
<h2>OWASP Top 10 for LLM Applications (2025) coverage</h2>
<table><tr><th>ID</th><th>Category</th><th>Probes</th><th>Succeeded</th><th>Result</th></tr>
{"".join(owasp_rows)}</table>
<h2>Details</h2>
{"".join(details)}
</body></html>
"""
