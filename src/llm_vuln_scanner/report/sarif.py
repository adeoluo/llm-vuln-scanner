"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

One rule per probe (with OWASP and ATLAS identifiers as tags and a
``security-severity`` score GitHub uses to rank alerts) and one result per probe that
found a vulnerability. LLM applications have no source line to point at, so results are
anchored to a configurable artifact (the application profile or prompt file, by
default ``llm-app``) and carry a fingerprint of probe and target so repeated scans
update the same alert instead of opening new ones.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from llm_vuln_scanner.taxonomy import ATLAS, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/adeoluo/llm-vuln-scanner"


def _rule(f: dict[str, Any]) -> dict[str, Any]:
    sev = Severity.parse(f["severity"])
    atlas = ", ".join(f"{t} {ATLAS[t].name}" if t in ATLAS else t for t in f["atlas"])
    md = (
        f"**{f['title']}**\n\n{f['description']}\n\n"
        f"OWASP {f['owasp']} {f['owasp_name']}; MITRE ATLAS {atlas}.\n\n"
        f"**Remediation:** {f['remediation']}"
    )
    return {
        "id": f["probe"],
        "name": "".join(p.title() for p in f["probe"].replace(".", "_").split("_")),
        "shortDescription": {"text": f["title"]},
        "fullDescription": {"text": f["description"]},
        "helpUri": f"https://genai.owasp.org/llm-top-10/#{f['owasp'].lower()}",
        "help": {"text": f["remediation"], "markdown": md},
        "defaultConfiguration": {"level": sev.sarif_level},
        "properties": {
            "tags": ["security", "llm", f["owasp"], *f["atlas"]],
            "security-severity": sev.security_severity,
            "precision": "high",
        },
    }


def render_sarif(report: dict[str, Any], artifact: str = "llm-app") -> str:
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
            "properties": {"successes": f["successes"], "attempts": f["attempts"],
                           "rate": f["rate"], "owasp": f["owasp"], "atlas": f["atlas"]},
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
            }},
            "automationDetails": {"id": f"llm-vuln-scanner/{report['target']}"},
            "invocations": [{"executionSuccessful": True,
                             "startTimeUtc": report["started_at"]}],
            "properties": {"target": report["target"], "summary": report["summary"]},
            "results": results,
        }],
    }  # fmt: skip
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
