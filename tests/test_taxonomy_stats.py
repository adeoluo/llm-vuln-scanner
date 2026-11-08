"""Taxonomy lookups and interval statistics."""

from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from llm_vuln_scanner import stats
from llm_vuln_scanner.taxonomy import ATLAS, OWASP, Severity, atlas, owasp


def test_owasp_has_ten_categories_in_order() -> None:
    assert list(OWASP) == [f"LLM{i:02d}" for i in range(1, 11)]
    assert owasp("LLM07").name == "Misinformation"
    assert owasp("LLM08:2026").name == "Hidden Context Exposure"
    with pytest.raises(ValueError, match="2025 edition"):
        owasp("LLM07:2025")
    with pytest.raises(ValueError):
        owasp("LLM11")


def test_atlas_lookup_and_url() -> None:
    t = atlas("AML.T0051.001")
    assert t.name == "Indirect"
    assert t.url.endswith("AML.T0051.001")
    assert all(k.startswith("AML.T") for k in ATLAS)
    with pytest.raises(ValueError):
        atlas("AML.T9999")


def test_severity_parse_and_levels() -> None:
    assert Severity.parse(" High ") is Severity.HIGH
    assert Severity.CRITICAL.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.LOW.sarif_level == "note"
    assert float(Severity.CRITICAL.security_severity) > float(Severity.HIGH.security_severity)
    with pytest.raises(ValueError):
        Severity.parse("severe")


def test_wilson_known_values() -> None:
    # Reference values from the closed form (Brown, Cai and DasGupta 2001, eq. 4).
    lo, hi = stats.wilson(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-4)
    assert hi == pytest.approx(0.7634, abs=1e-4)
    assert stats.wilson(0, 10)[0] == 0.0
    assert stats.wilson(10, 10)[1] == 1.0
    assert stats.wilson(0, 0) == (0.0, 1.0)
    with pytest.raises(ValueError):
        stats.wilson(3, 2)


@given(st.integers(0, 500), st.integers(1, 500))
def test_wilson_contains_point_estimate(k: int, n: int) -> None:
    k = min(k, n)
    lo, hi = stats.wilson(k, n)
    assert 0.0 <= lo <= k / n <= hi <= 1.0


@given(st.integers(1, 200), st.integers(1, 200), st.integers(0, 200), st.integers(0, 200))
def test_newcombe_contains_difference(n1: int, n2: int, k1: int, k2: int) -> None:
    k1, k2 = min(k1, n1), min(k2, n2)
    d, lo, hi = stats.newcombe_diff(k1, n1, k2, n2)
    assert -1.0 <= lo <= d <= hi <= 1.0
    assert math.isclose(d, k1 / n1 - k2 / n2)


def test_newcombe_rejects_empty() -> None:
    with pytest.raises(ValueError):
        stats.newcombe_diff(0, 0, 1, 2)


def test_percentile() -> None:
    assert stats.percentile([1, 2, 3, 4], 50) == 2.5
    assert stats.percentile([7], 99) == 7
    with pytest.raises(ValueError):
        stats.percentile([], 50)
    with pytest.raises(ValueError):
        stats.percentile([1], 101)
