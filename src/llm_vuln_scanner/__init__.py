"""LLM Vuln Scanner: probes, detectors and reports for LLM application security testing.

Quick use::

    from llm_vuln_scanner import Scanner, ScanConfig
    from llm_vuln_scanner.targets import NaiveModel

    report = Scanner(NaiveModel(), ScanConfig(probes=["injection.direct"])).run()
    report.to_dict()["summary"]
"""

__version__ = "0.1.0"

from llm_vuln_scanner.engine import ScanConfig, Scanner, ScanReport

__all__ = ["ScanConfig", "ScanReport", "Scanner", "__version__"]
