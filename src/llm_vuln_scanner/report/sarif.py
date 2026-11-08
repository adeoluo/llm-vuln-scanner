"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

One rule per probe and one result per probe that found a vulnerability. The three
frameworks are SARIF taxonomies (``runs[].taxonomies``: the OWASP Top 10 for LLM
Applications 2026, the OWASP Top 10 for Agentic Applications 2026 and MITRE ATLAS
v2026.10, each listing its categories as ``taxa``); every rule points at its categories
through ``relationships`` and every result through ``taxa``. Rules also carry the
identifiers as tags (``LLM03:2026``, ``ASI02:2026``, ``AML.T0053``), which GitHub code
scanning shows as filters, and a ``security-severity`` score GitHub uses to rank alerts. LLM applications have no source line to point at, so results are
anchored to a configurable artifact (the application profile or prompt file, by
default ``llm-app``) and carry a fingerprint of probe and target so repeated scans
update the same alert instead of opening new ones.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from llm_vuln_scanner.report.taxonomy import upgrade_report
from llm_vuln_scanner.taxonomy import (
    AGENTIC,
    ATLAS,
    ATLAS_NAME,
    ATLAS_URI,
    ATLAS_VERSION,
    OWASP,
    OWASP_AGENTIC_NAME,
    OWASP_AGENTIC_URI,
    OWASP_AGENTIC_VERSION,
    OWASP_LLM_NAME,
    OWASP_LLM_URI,
    OWASP_LLM_VERSION,
    Severity,
)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/adeoluo/llm-vuln-scanner"


# Taxonomy index in runs[].taxonomies, its entries and the taxon key of a finding.
_TAXONOMIES: tuple[tuple[str, str, str, str, dict[str, Any]], ...] = (
    (OWASP_LLM_NAME, OWASP_LLM_VERSION, OWASP_LLM_URI, "OWASP GenAI Security Project", OWASP),
    (OWASP_AGENTIC_NAME, OWASP_AGENTIC_VERSION, OWASP_AGENTIC_URI, "OWASP GenAI Security Project", AGENTIC),
    (ATLAS_NAME, ATLAS_VERSION, ATLAS_URI, "MITRE", ATLAS),
)


def _taxonomies() -> list[dict[str, Any]]:
    return [
        {"name": name, "version": version, "informationUri": uri, "organization": org,
         "isComprehensive": table is not ATLAS,
         "taxa": [{"id": k, "name": v.display if table is ATLAS else v.name, "helpUri": v.url}
                  for k, v in table.items()]}
        for name, version, uri, org, table in _TAXONOMIES
    ]  # fmt: skip


def _taxa_refs(f: dict[str, Any]) -> list[dict[str, Any]]:
    """References from a finding to its OWASP LLM, OWASP Agentic and ATLAS taxa."""
    refs = []
    for ti, (name, _, _, _, table) in enumerate(_TAXONOMIES):
        ids = [f["owasp"]] if table is OWASP else (f["asi"] if table is AGENTIC else f["atlas"])
        keys = list(table)
        for k in ids:
            if k in table:
                refs.append({"id": k, "index": keys.index(k), "toolComponent": {"name": name, "index": ti}})
    return refs


def _rule(f: dict[str, Any]) -> dict[str, Any]:
    sev = Severity.parse(f["severity"])
    atlas = ", ".join(f"{t} {n}" for t, n in zip(f["atlas"], f["atlas_names"], strict=True))
    agentic = ", ".join(f"{r} {n}" for r, n in zip(f["asi"], f["asi_names"], strict=True))
    md = (
        f"**{f['title']}**\n\n{f['description']}\n\n"
        f"OWASP {f['owasp_ref']} {f['owasp_name']}"
        + (f"; OWASP Agentic {OWASP_AGENTIC_VERSION} {agentic}" if agentic else "")
        + f"; MITRE ATLAS v{ATLAS_VERSION} {atlas}.\n\n"
        f"**Remediation:** {f['remediation']}"
    )
    tags = [
        "security",
        "llm",
        f["owasp_ref"],
        *(f"{r}:{OWASP_AGENTIC_VERSION}" for r in f["asi"]),
        *f["atlas"],
    ]
    return {
        "id": f["probe"],
        "name": "".join(p.title() for p in f["probe"].replace(".", "_").split("_")),
        "shortDescription": {"text": f["title"]},
        "fullDescription": {"text": f["description"]},
        "helpUri": f["owasp_url"],
        "help": {"text": f["remediation"], "markdown": md},
        "defaultConfiguration": {"level": sev.sarif_level},
        "relationships": [{"target": ref, "kinds": ["relevant"]} for ref in _taxa_refs(f)],
        "properties": {
            "tags": tags,
            "security-severity": sev.security_severity,
            "precision": "high",
        },
    }


def render_sarif(report: dict[str, Any], artifact: str = "llm-app") -> str:
    report = upgrade_report(report)
    findings = report["findings"]
    rules = [_rule(f) for f in findings]
    index = {f["probe"]: i for i, f in enumerate(findings)}
    results = []
    for f in findings:
        if not f["vulnerable"]:
            continue
        sev = Severity.parse(f["severity"])
        lo, hi = f["ci95"]
        msg = (
            f"{f['title']}: {f['successes']} of {f['attempts']} attempts succeeded against "
            f"{report['target']} (rate {f['rate']:.1%}, 95% CI {lo:.1%} to {hi:.1%})."
        )
        if f["examples"]:
            ev = "; ".join(f["examples"][0]["evidence"])
            msg += f" Example: {ev}"
        fp = hashlib.sha256(f"{report['target']}|{f['probe']}".encode()).hexdigest()[:32]
        results.append({
            "ruleId": f["probe"],
            "ruleIndex": index[f["probe"]],
            "level": sev.sarif_level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": artifact},
                "region": {"startLine": 1},
            }}],
            "partialFingerprints": {"llmVulnScanner/v1": fp},
            "taxa": _taxa_refs(f),
            "properties": {"successes": f["successes"], "attempts": f["attempts"],
                           "rate": f["rate"], "owasp": f["owasp_ref"], "asi": f["asi"],
                           "atlas": f["atlas"]},
        })  # fmt: skip
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "llm-vuln-scanner",
                "version": report["tool"]["version"],
                "semanticVersion": report["tool"]["version"],
                "informationUri": INFO_URI,
                "rules": rules,
                "supportedTaxonomies": [{"name": t[0], "index": i} for i, t in enumerate(_TAXONOMIES)],
            }},
            "taxonomies": _taxonomies(),
            "automationDetails": {"id": f"llm-vuln-scanner/{report['target']}"},
            "invocations": [{"executionSuccessful": True,
                             "startTimeUtc": report["started_at"]}],
            "properties": {"target": report["target"], "summary": report["summary"],
                           "taxonomy": report["taxonomy"]},
            "results": results,
        }],
    }  # fmt: skip
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
