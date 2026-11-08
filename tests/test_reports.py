"""Report formats: JSON, SARIF (schema-validated), JUnit, HTML (escaping), markdown."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner.detectors.sinks import active_html
from llm_vuln_scanner.report import RENDERERS, github_annotations
from llm_vuln_scanner.report.sarif import render_sarif
from llm_vuln_scanner.targets.base import CallableTarget
from llm_vuln_scanner.targets.mock import NaiveModel
from llm_vuln_scanner.taxonomy import Severity

SCHEMA = Path(__file__).parent / "data" / "sarif-schema-2.1.0.json"


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    return Scanner(NaiveModel(), ScanConfig(probes=["output", "leakage", "dos"], sample=6)).run().to_dict()


def test_json_round_trip(report: dict[str, Any]) -> None:
    assert json.loads(RENDERERS["json"](report)) == report


def test_sarif_structure(report: dict[str, Any]) -> None:
    sarif = json.loads(render_sarif(report, "app.json"))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {f["probe"] for f in report["findings"]}
    assert all("security-severity" in r["properties"] for r in rules.values())
    vuln = [f for f in report["findings"] if f["vulnerable"]]
    assert len(run["results"]) == len(vuln) > 0
    for res in run["results"]:
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.json"
        assert run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["partialFingerprints"]


@pytest.mark.validation
def test_sarif_validates_against_the_official_schema(report: dict[str, Any]) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text())
    jsonschema.validate(json.loads(render_sarif(report)), schema)


def test_junit(report: dict[str, Any]) -> None:
    root = ET.fromstring(RENDERERS["junit"](report).split("\n", 1)[1])
    assert root.tag == "testsuites"
    assert int(root.get("tests", "0")) == len(report["attempts"])
    assert int(root.get("failures", "0")) == sum(a["success"] for a in report["attempts"])
    suites = root.findall("testsuite")
    assert {s.get("name") for s in suites} == {f["probe"] for f in report["findings"]}


def test_junit_errors() -> None:
    def boom(a: object) -> str:
        raise RuntimeError("x")

    d = Scanner(CallableTarget(boom), ScanConfig(probes=["dos"])).run().to_dict()
    root = ET.fromstring(RENDERERS["junit"](d).split("\n", 1)[1])
    assert root.get("errors") == "12"


def test_html_is_escaped_even_with_hostile_responses() -> None:
    hostile = CallableTarget(lambda a: "<script>alert(1)</script><img src=x onerror=alert(2)> " + a.last_user)
    d = Scanner(hostile, ScanConfig(probes=["output.xss", "injection.direct"], sample=8)).run().to_dict()
    page = RENDERERS["html"](d)
    assert "<!doctype html>" in page and "Content-Security-Policy" in page
    assert active_html(page) == []
    assert "&lt;script&gt;" in page


def test_markdown_and_annotations(report: dict[str, Any], tmp_path: Path) -> None:
    md = RENDERERS["markdown"](report)
    assert md.startswith("## LLM vulnerability scan")
    assert "| LLM06:2026 Unbounded Consumption | yes |" in md
    assert "| LLM10:2026 Improper Output Handling | yes |" in md
    assert "| ASI10:2026 Rogue Agents | no | not tested |" in md
    assert "2025" not in md
    ann = github_annotations(report, Severity.CRITICAL)
    assert "::error title=output.sql" in ann
    assert "::warning title=" in ann
    clean = (
        Scanner(CallableTarget(lambda a: "I'm sorry, but I can't."), ScanConfig(probes=["dos"]))
        .run()
        .to_dict()
    )
    assert github_annotations(clean) == ""
