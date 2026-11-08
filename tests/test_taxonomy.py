"""Pins the taxonomy to the 2026 frameworks.

The OWASP Top 10 for LLM Applications changed its numbering between 2025 and 2026 and
ATLAS v2026.10 retired AML.T0056 and AML.T0057, so a silent fallback to older
identifiers would mislabel every finding. These tests fix the exact identifiers and
names, check every ATLAS technique against the technique list of the v2026.10 data
release (tests/data/atlas-2026.10-techniques.json, written by scripts/atlas_snapshot.py),
pin each probe's mapping, and check that every report format carries the 2026 labels.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner import probes as pr
from llm_vuln_scanner.cli import main
from llm_vuln_scanner.report import RENDERERS, upgrade_report
from llm_vuln_scanner.report.sarif import render_sarif
from llm_vuln_scanner.report.taxonomy import ATLAS_MOVED
from llm_vuln_scanner.targets.mock import NaiveModel
from llm_vuln_scanner.taxonomy import (
    AGENTIC,
    ATLAS,
    ATLAS_VERSION,
    OWASP,
    OWASP_2025_TO_2026,
    OWASP_AGENTIC_VERSION,
    OWASP_LLM_VERSION,
    agentic,
    atlas,
)

SNAPSHOT = json.loads((Path(__file__).parent / "data" / "atlas-2026.10-techniques.json").read_text())

OWASP_LLM_2026 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Excessive Agency",
    "LLM04": "Supply Chain",
    "LLM05": "Data and Model Poisoning",
    "LLM06": "Unbounded Consumption",
    "LLM07": "Misinformation",
    "LLM08": "Hidden Context Exposure",
    "LLM09": "Vector and Embedding Weaknesses",
    "LLM10": "Improper Output Handling",
}
OWASP_AGENTIC_2026 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
# probe -> (OWASP LLM 2026, OWASP Agentic 2026, ATLAS v2026.10)
PROBE_MAP: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "injection.direct": ("LLM01", (), ("AML.T0051.000",)),
    "injection.indirect": ("LLM01", (), ("AML.T0051.001", "AML.T0070")),
    "encoding.obfuscation": ("LLM01", (), ("AML.T0068", "AML.T0051.000")),
    "jailbreak.templates": ("LLM01", (), ("AML.T0054",)),
    "disclosure.secrets": ("LLM02", (), ("AML.T0085.002", "AML.T0055")),
    "agency.tools": ("LLM03", ("ASI01", "ASI02"), ("AML.T0053", "AML.T0086", "AML.T0101", "AML.T0051.001")),
    "dos.token_blowup": ("LLM06", (), ("AML.T0029", "AML.T0034.001")),
    "leakage.system_prompt": ("LLM08", (), ("AML.T0085.003", "AML.T0069.002")),
    "output.xss": ("LLM10", (), ("AML.T0077",)),
    "output.sql": ("LLM10", (), ("AML.T0050", "AML.T0077")),
    "output.shell": ("LLM10", ("ASI05",), ("AML.T0050",)),
    "dataset.tensortrust_hijacking": ("LLM01", (), ("AML.T0051.000",)),
    "dataset.tensortrust_extraction": ("LLM08", (), ("AML.T0085.003", "AML.T0069.002")),
    "dataset.gandalf": ("LLM08", (), ("AML.T0085.003", "AML.T0069.002")),
    "dataset.wild_jailbreak": ("LLM01", (), ("AML.T0054",)),
}


def test_versions_are_2026() -> None:
    assert OWASP_LLM_VERSION == "2026"
    assert OWASP_AGENTIC_VERSION == "2026"
    assert ATLAS_VERSION == "2026.10" == SNAPSHOT["version"]


def test_owasp_llm_2026_ids_and_names_are_pinned() -> None:
    assert {k: v.name for k, v in OWASP.items()} == OWASP_LLM_2026
    assert list(OWASP) == list(OWASP_LLM_2026)
    for k, cat in OWASP.items():
        assert cat.ref == f"{k}:2026"
        assert "/2026/final/" in cat.url and cat.url.endswith(".md")


def test_owasp_agentic_2026_ids_and_names_are_pinned() -> None:
    assert {k: v.name for k, v in AGENTIC.items()} == OWASP_AGENTIC_2026
    assert agentic("ASI02:2026").name == "Tool Misuse & Exploitation"
    with pytest.raises(ValueError):
        agentic("ASI11")
    with pytest.raises(ValueError, match="2025 edition"):
        agentic("ASI01:2025")


def test_atlas_techniques_exist_in_the_v2026_10_release_with_the_same_names() -> None:
    assert SNAPSHOT["sha256"] == "ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d"
    assert len(SNAPSHOT["techniques"]) == 221 and len(SNAPSHOT["tactics"]) == 16
    for tid, t in ATLAS.items():
        assert SNAPSHOT["techniques"].get(tid) == t.name, tid
        if t.parent:
            assert t.parent in ATLAS, f"{tid}: parent {t.parent} missing"


def test_retired_atlas_ids_are_not_used() -> None:
    for old, new in ATLAS_MOVED.items():
        assert old not in SNAPSHOT["techniques"] and old not in ATLAS
        assert new in SNAPSHOT["techniques"] and new in ATLAS
    for name in pr.names():
        assert not set(pr.get(name).info.atlas) & set(ATLAS_MOVED), name


def test_atlas_display_names() -> None:
    assert atlas("AML.T0051.001").display == "LLM Prompt Injection: Indirect"
    assert atlas("AML.T0085.003").display == "Data from AI Services: System Instructions"
    assert atlas("AML.T0053").display == "AI Agent Tool Invocation"
    assert atlas("AML.T0053").parent is None
    with pytest.raises(ValueError, match=r"2026\.10"):
        atlas("AML.T0056")


def test_every_probe_mapping_is_pinned() -> None:
    assert set(pr.names()) == set(PROBE_MAP)
    for name, (cid, asi, techniques) in PROBE_MAP.items():
        info = pr.get(name).info
        assert (info.owasp, info.asi, info.atlas) == (cid, asi, techniques), name


def test_every_tool_or_agent_probe_has_an_agentic_mapping() -> None:
    assert pr.get("agency.tools").info.asi == ("ASI01", "ASI02")
    for name in pr.names():
        info = pr.get(name).info
        if any(t in info.atlas for t in ("AML.T0053", "AML.T0086", "AML.T0101")):
            assert info.asi, name


def test_owasp_2025_to_2026_is_a_permutation() -> None:
    assert sorted(OWASP_2025_TO_2026) == sorted(OWASP_2025_TO_2026.values()) == list(OWASP)
    assert OWASP_2025_TO_2026["LLM06"] == "LLM03"  # Excessive Agency
    assert OWASP_2025_TO_2026["LLM05"] == "LLM10"  # Improper Output Handling
    assert OWASP_2025_TO_2026["LLM07"] == "LLM08"  # System Prompt Leakage -> Hidden Context Exposure
    assert OWASP_2025_TO_2026["LLM10"] == "LLM06"  # Unbounded Consumption


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    cfg = ScanConfig(probes=["agency", "leakage", "output.shell", "dos"], sample=4)
    return Scanner(NaiveModel(), cfg).run().to_dict()


def _as_2025(report: dict[str, Any]) -> dict[str, Any]:
    """The same report as schema 1 wrote it (2025 identifiers, ATLAS 5.6.0)."""
    old = json.loads(json.dumps(report))
    back = {v: k for k, v in OWASP_2025_TO_2026.items()}
    old["schema_version"] = "1"
    for key in ("taxonomy", "agentic"):
        old.pop(key)
    for f in old["findings"]:
        f["owasp"] = back[f["owasp"]]
        f["atlas"] = [{v: k for k, v in ATLAS_MOVED.items()}.get(t, t) for t in f["atlas"]]
        for key in ("owasp_ref", "owasp_url", "atlas_names", "asi", "asi_names"):
            f.pop(key)
    old["owasp"] = {k: {"name": "old", "url": "", "probes": [], "attempts": 0, "successes": 0,
                        "rate": None, "vulnerable": False, "tested": False} for k in OWASP}  # fmt: skip
    return old


def test_upgrade_relabels_a_2025_report(report: dict[str, Any]) -> None:
    old = _as_2025(report)
    assert {f["owasp"] for f in old["findings"]} >= {"LLM06", "LLM07"}
    new = upgrade_report(old)
    assert new is not old and old["schema_version"] == "1"
    assert new["taxonomy"]["upgraded_from_schema"] == "1"
    by = {f["probe"]: f for f in new["findings"]}
    assert by["agency.tools"]["owasp_ref"] == "LLM03:2026" and by["agency.tools"]["asi"] == ["ASI01", "ASI02"]
    assert by["leakage.system_prompt"]["atlas"] == ["AML.T0085.003", "AML.T0069.002"]
    for cid in OWASP:
        assert new["owasp"][cid]["successes"] == report["owasp"][cid]["successes"]
    assert new["agentic"] == report["agentic"]
    assert upgrade_report(report) is report


def test_upgrade_maps_unknown_probes_by_category(report: dict[str, Any]) -> None:
    old = _as_2025(report)
    old["findings"][0]["probe"] = "custom.retired_probe"
    old["findings"][0]["owasp"] = "LLM07"
    old["findings"][0]["atlas"] = ["AML.T0056", "AML.T0057"]
    f = upgrade_report(old)["findings"][0]
    assert (f["owasp"], f["owasp_name"]) == ("LLM08", "Hidden Context Exposure")
    assert f["atlas"] == ["AML.T0085.003", "AML.T0085.002"] and f["asi"] == []


def test_reports_carry_the_2026_taxonomies(report: dict[str, Any]) -> None:
    assert report["taxonomy"] == {"owasp_llm": "2026", "owasp_agentic": "2026", "atlas": "2026.10"}
    assert report["agentic"]["ASI02"]["probes"] == ["agency.tools"]
    assert report["agentic"]["ASI05"]["probes"] == ["output.shell"]
    for fmt, text in ((f, RENDERERS[f](report)) for f in ("json", "html", "markdown", "junit")):
        assert "2025" not in text, fmt
        assert "AML.T0056" not in text and "AML.T0057" not in text, fmt
    html = RENDERERS["html"](report)
    assert "OWASP Top 10 for LLM Applications 2026</a> coverage" in html
    assert "OWASP Top 10 for Agentic Applications 2026</a> coverage" in html
    assert "MITRE ATLAS v2026.10" in html
    assert "LLM03:2026" in html and "Tool Misuse &amp; Exploitation" in html


def test_junit_properties_name_the_editions(report: dict[str, Any]) -> None:
    root = ET.fromstring(RENDERERS["junit"](report).split("\n", 1)[1])
    props = {
        s.get("name"): {p.get("name"): p.get("value") for p in s.iter("property")}
        for s in root.findall("testsuite")
    }
    assert props["agency.tools"]["owasp"] == "LLM03:2026"
    assert props["agency.tools"]["owasp_agentic"] == "ASI01:2026 ASI02:2026"
    assert props["leakage.system_prompt"]["owasp"] == "LLM08:2026"
    assert props["dos.token_blowup"]["atlas_version"] == "2026.10"


def test_sarif_taxonomies_and_relationships(report: dict[str, Any]) -> None:
    run = json.loads(render_sarif(report))["runs"][0]
    tax = {t["name"]: t for t in run["taxonomies"]}
    assert tax["OWASP Top 10 for LLM Applications"]["version"] == "2026"
    assert tax["OWASP Top 10 for Agentic Applications"]["version"] == "2026"
    assert tax["MITRE ATLAS"]["version"] == "2026.10"
    assert [t["id"] for t in tax["OWASP Top 10 for LLM Applications"]["taxa"]] == list(OWASP_LLM_2026)
    names = [t["name"] for t in run["taxonomies"]]
    assert [s["name"] for s in run["tool"]["driver"]["supportedTaxonomies"]] == names
    for rule in run["tool"]["driver"]["rules"]:
        for rel in rule["relationships"]:
            ref = rel["target"]
            component = run["taxonomies"][ref["toolComponent"]["index"]]
            assert component["name"] == ref["toolComponent"]["name"]
            assert component["taxa"][ref["index"]]["id"] == ref["id"]
    agency = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "agency.tools")
    assert {"LLM03:2026", "ASI01:2026", "ASI02:2026", "AML.T0053"} <= set(agency["properties"]["tags"])
    assert agency["helpUri"].endswith("2026/final/LLM03_ExcessiveAgency.md")
    for res in run["results"]:
        assert res["taxa"] and res["properties"]["owasp"].endswith(":2026")


def test_cli_taxonomy(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["taxonomy"]) == 0
    out = capsys.readouterr().out
    assert "OWASP Top 10 for LLM Applications 2026" in out
    assert "OWASP Top 10 for Agentic Applications 2026" in out
    assert "MITRE ATLAS v2026.10" in out
    assert re.search(r"LLM03:2026\s+Excessive Agency\s+agency\.tools", out)
    assert re.search(r"LLM04:2026\s+Supply Chain\s+\(not covered\)", out)
    assert main(["taxonomy", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["versions"]["atlas"] == "2026.10"
    assert data["owasp_agentic"]["ASI02:2026"]["probes"] == ["agency.tools"]
    assert data["atlas"]["AML.T0085.003"]["probes"] == [
        "dataset.gandalf", "dataset.tensortrust_extraction", "leakage.system_prompt"
    ]  # fmt: skip


def test_no_retired_identifiers_in_the_package() -> None:
    src = Path(__file__).resolve().parents[1] / "src" / "llm_vuln_scanner"
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"LLM\d\d:2025", text), path
        assert "(2025)" not in text, path
        if re.search(r"AML\.T005[67]\b", text):
            # taxonomy.py documents the move; report/taxonomy.py maps reports from 0.1 builds
            assert path.name == "taxonomy.py", path
