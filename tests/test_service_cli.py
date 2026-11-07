"""HTTP service and command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from llm_vuln_scanner import cli
from llm_vuln_scanner.service import serve
from tests.test_demo_app import get, post


def test_service_routes(serve_http: Any) -> None:
    base = serve_http(serve(port=0))
    assert json.loads(get(base + "/health")[1])["status"] == "ok"
    assert json.loads(get(base + "/ready")[1])["probes"] >= 15
    probes = json.loads(get(base + "/v1/probes")[1])
    assert any(p["name"] == "agency.tools" for p in probes)
    status, body = post(base + "/v1/scans", {"target": "naive", "probes": ["dos"], "sample": 3})
    assert status == 200 and body["summary"]["attempts"] == 3
    assert post(base + "/v1/scans", {"target": "openai:http://169.254.169.254/v1"})[0] == 403
    for bad in ({}, {"target": "naive", "probes": "x"}, {"target": "naive", "format": "pdf"},
                {"target": "naive", "sample": 0}, {"target": "naive", "seed": "x"}):  # fmt: skip
        assert post(base + "/v1/scans", bad)[0] == 400, bad
    assert post(base + "/v1/nope", {"a": 1})[0] == 404
    assert post(base + "/v1/scans", [1])[0] == 400
    assert get(base + "/nope")[0] == 404
    m = get(base + "/metrics")[1]
    assert "lvs_attempts_total 3" in m and 'lvs_request_seconds_bucket{le="+Inf"}' in m


def test_service_rejects_large_scans(serve_http: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import llm_vuln_scanner.service as svc

    monkeypatch.setattr(svc, "MAX_ATTEMPTS", 5)
    base = serve_http(serve(port=0))
    status, body = post(base + "/v1/scans", {"target": "naive", "probes": ["dos"]})
    assert status == 400 and "too large" in body["error"]


def test_service_sarif_format(serve_http: Any) -> None:
    import urllib.request

    base = serve_http(serve(port=0))
    req = urllib.request.Request(base + "/v1/scans", method="POST",
                                 data=json.dumps({"target": "naive", "probes": ["output.sql"],
                                                  "sample": 2, "format": "sarif"}).encode())  # fmt: skip
    with urllib.request.urlopen(req, timeout=30) as r:
        assert r.headers["Content-Type"] == "application/sarif+json"
        assert json.loads(r.read())["version"] == "2.1.0"


def test_cli_scan_writes_reports_and_fails_on_severity(tmp_path: Path, capsys: pytest.CaptureFixture[str],
                                                       monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    code = cli.main(["scan", "--target", "naive", "--probes", "output.sql,dos", "--sample", "4",
                     "--out", str(tmp_path), "--fail-on", "critical", "--github"])  # fmt: skip
    out = capsys.readouterr().out
    assert code == 1
    assert "::error title=output.sql" in out
    for ext in ("json", "html", "sarif", "xml", "md"):
        assert (tmp_path / f"scan.{ext}").exists()
    assert summary.read_text().startswith("## LLM vulnerability scan")
    code = cli.main(["scan", "--target", "refusing", "--probes", "dos", "--out", str(tmp_path),
                     "--name", "clean", "--fail-on", "low", "--quiet", "--format", "json"])  # fmt: skip
    assert code == 0 and (tmp_path / "clean.json").exists()


def test_cli_listing_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["probes"]) == 0
    assert "agency.tools" in capsys.readouterr().out
    assert cli.main(["probes", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["name"]
    assert cli.main(["detectors"]) == 0
    assert "refusal_classifier" in capsys.readouterr().out
    assert cli.main(["taxonomy"]) == 0
    assert "(not covered)" in capsys.readouterr().out
    assert cli.main(["info"]) == 0
    assert json.loads(capsys.readouterr().out)["version"]


def test_cli_report_and_compare(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["scan", "--target", "naive", "--probes", "output", "--out", str(tmp_path), "--name", "a",
              "--format", "json", "--quiet"])  # fmt: skip
    cli.main(["scan", "--target", "refusing", "--probes", "output", "--out", str(tmp_path), "--name", "b",
              "--format", "json", "--quiet"])  # fmt: skip
    assert cli.main(["report", str(tmp_path / "a.json"), "--out", str(tmp_path / "r")]) == 0
    assert (tmp_path / "r" / "a.sarif").exists()
    capsys.readouterr()
    assert cli.main(["compare", str(tmp_path / "a.json"), str(tmp_path / "b.json")]) == 0
    assert "output.sql" in capsys.readouterr().out


def test_cli_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan", "--target", "bogus", "--out", str(tmp_path)]) == 2
    assert cli.main(["scan", "--target", "naive", "--probes", "dos", "--format", "pdf",
                     "--out", str(tmp_path), "--quiet"]) == 2  # fmt: skip
    assert "error:" in capsys.readouterr().err


def test_cli_profile_and_judge(tmp_path: Path, serve_http: Any) -> None:
    from llm_vuln_scanner.demo_app import DemoApp
    from llm_vuln_scanner.demo_app import serve as serve_demo
    from llm_vuln_scanner.targets.mock import NaiveModel

    base = serve_http(serve_demo(DemoApp(NaiveModel()), port=0))
    profile = Path(__file__).resolve().parents[1] / "examples" / "demo-app.json"
    code = cli.main(["scan", "--target", f"app:{base}", "--profile", str(profile), "--probes", "output.shell",
                     "--out", str(tmp_path), "--quiet", "--format", "sarif"])  # fmt: skip
    assert code == 0
    sarif = json.loads((tmp_path / "scan.sarif").read_text())
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ].endswith("demo-app.json")
    assert cli.main(["scan", "--target", "naive", "--probes", "jailbreak", "--sample", "3", "--judge", "naive",
                     "--out", str(tmp_path), "--quiet", "--format", "json"]) == 0  # fmt: skip
    rep = json.loads((tmp_path / "scan.json").read_text())
    assert any(d["detector"] == "judge" for a in rep["attempts"] for d in a["detections"])
