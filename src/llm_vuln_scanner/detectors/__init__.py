"""Detectors package; see :mod:`llm_vuln_scanner.detectors.base`."""

from llm_vuln_scanner.detectors.base import Detector, available, build, register

__all__ = ["Detector", "available", "build", "register"]
