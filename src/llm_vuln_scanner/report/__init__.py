"""Report renderers. Every format is produced from the JSON report dict
(:meth:`llm_vuln_scanner.engine.ScanReport.to_dict`), so a saved JSON report can be
re-rendered in any other format later (``llm-vuln-scanner report``)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from llm_vuln_scanner.report.html import render_html
from llm_vuln_scanner.report.junit import render_junit
from llm_vuln_scanner.report.markdown import github_annotations, render_markdown
from llm_vuln_scanner.report.sarif import render_sarif


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


RENDERERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "json": render_json,
    "html": render_html,
    "sarif": render_sarif,
    "junit": render_junit,
    "markdown": render_markdown,
}
EXTENSIONS = {"json": "json", "html": "html", "sarif": "sarif", "junit": "xml", "markdown": "md"}

__all__ = ["EXTENSIONS", "RENDERERS", "github_annotations", "render_json"]
