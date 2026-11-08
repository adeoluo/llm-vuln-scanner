"""JUnit XML output: one test suite per probe, one test case per attempt.

A succeeded attack is a test *failure*, so CI systems that read JUnit (GitHub Actions
test reporters, GitLab, Jenkins) show the vulnerable attempts as failing tests. Target
errors are reported as JUnit *errors*. Each suite's properties name its OWASP LLM 2026
category, OWASP Agentic 2026 risks and ATLAS v2026.10 techniques, with the editions.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from xml.etree import ElementTree as ET

from llm_vuln_scanner.report.taxonomy import upgrade_report


def render_junit(report: dict[str, Any]) -> str:
    report = upgrade_report(report)
    tax = report["taxonomy"]
    attempts = report.get("attempts", [])
    by_probe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in attempts:
        by_probe[a["probe"]].append(a)
    root = ET.Element("testsuites", name=f"llm-vuln-scanner: {report['target']}")
    total = failures = errors = 0
    for f in report["findings"]:
        cases = by_probe.get(f["probe"], [])
        n_err = sum(1 for a in cases if a.get("error"))
        suite = ET.SubElement(
            root, "testsuite", name=f["probe"], tests=str(len(cases)),
            failures=str(sum(1 for a in cases if a["success"])), errors=str(n_err),
        )  # fmt: skip
        props = ET.SubElement(suite, "properties")
        for k, v in (
            ("owasp", f["owasp_ref"]), ("owasp_name", f["owasp_name"]),
            ("owasp_agentic", " ".join(f"{r}:{tax['owasp_agentic']}" for r in f["asi"])),
            ("atlas", " ".join(f["atlas"])), ("atlas_version", tax["atlas"]), ("severity", f["severity"]),
        ):  # fmt: skip
            ET.SubElement(props, "property", name=k, value=v)
        for a in cases:
            case = ET.SubElement(suite, "testcase", classname=f["probe"],
                                 name=f"{a['id']}#{a['generation']}",
                                 time=f"{a.get('latency_s') or 0:.3f}")  # fmt: skip
            if a.get("error"):
                ET.SubElement(case, "error", message=str(a["error"])[:200])
            elif a["success"]:
                ev = "; ".join(f"{d['detector']}: {d['evidence']}" for d in a["detections"] if d["hit"])
                fail = ET.SubElement(case, "failure", message=ev[:300] or "attack succeeded",
                                     type=f["severity"])  # fmt: skip
                fail.text = a.get("response", "")
        total += len(cases)
        failures += sum(1 for a in cases if a["success"])
        errors += n_err
    root.set("tests", str(total))
    root.set("failures", str(failures))
    root.set("errors", str(errors))
    root.set("time", f"{report.get('duration_s', 0):.3f}")
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
