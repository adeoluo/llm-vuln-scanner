"""Taxonomy fields of a JSON report, and upgrading reports written by earlier releases.

Reports from schema version 1 used the OWASP LLM Top 10 2025 identifiers and ATLAS 5.6.0
(for example ``LLM06`` for excessive agency and ``AML.T0056`` for system prompt
extraction). :func:`upgrade_report` re-labels such a report with the current
frameworks: findings of known probes take the probe's current mappings, others are
mapped with :data:`~llm_vuln_scanner.taxonomy.OWASP_2025_TO_2026`, and the per-category
summaries are rebuilt. Attack counts are never changed.
"""

from __future__ import annotations

import copy
from typing import Any

from llm_vuln_scanner.taxonomy import (
    AGENTIC,
    ATLAS,
    OWASP,
    OWASP_2025_TO_2026,
    OWASP_LLM_VERSION,
    versions,
)

# ATLAS identifiers retired by v2026.10 and the techniques they moved to.
ATLAS_MOVED = {"AML.T0056": "AML.T0085.003", "AML.T0057": "AML.T0085.002"}


def _summary(findings: list[dict[str, Any]], key: str, table: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for cid, cat in table.items():
        fs = [f for f in findings if (f[key] == cid if key == "owasp" else cid in f.get(key, []))]
        k = sum(f["successes"] for f in fs)
        n = sum(f["attempts"] for f in fs)
        out[cid] = {
            "ref": cat.ref, "name": cat.name, "url": cat.url, "probes": [f["probe"] for f in fs],
            "attempts": n, "successes": k, "rate": k / n if n else None,
            "vulnerable": any(f["vulnerable"] for f in fs), "tested": bool(fs),
        }  # fmt: skip
    return out


def upgrade_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return ``report`` with current taxonomy fields (a copy if anything changes)."""
    if report.get("taxonomy", {}).get("owasp_llm") == OWASP_LLM_VERSION and "agentic" in report:
        return report
    from llm_vuln_scanner import probes as pr

    known = set(pr.names())
    out = copy.deepcopy(report)
    for f in out["findings"]:
        if f["probe"] in known:
            info = pr.get(f["probe"]).info
            f["owasp"], f["atlas"], f["asi"] = info.owasp, list(info.atlas), list(info.asi)
        else:
            f["owasp"] = OWASP_2025_TO_2026.get(f["owasp"], f["owasp"])
            f["atlas"] = [ATLAS_MOVED.get(t, t) for t in f["atlas"]]
            f.setdefault("asi", [])
        cat = OWASP[f["owasp"]]
        f["owasp_ref"], f["owasp_name"], f["owasp_url"] = cat.ref, cat.name, cat.url
        f["atlas_names"] = [ATLAS[t].display if t in ATLAS else t for t in f["atlas"]]
        f["asi_names"] = [AGENTIC[r].name for r in f["asi"]]
    out["owasp"] = _summary(out["findings"], "owasp", OWASP)
    out["agentic"] = _summary(out["findings"], "asi", AGENTIC)
    out["taxonomy"] = {**versions(), "upgraded_from_schema": str(report.get("schema_version", "1"))}
    return out
