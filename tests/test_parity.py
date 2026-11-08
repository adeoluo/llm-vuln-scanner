"""Rust core against the Python reference implementations."""

from __future__ import annotations

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from llm_vuln_scanner import _backend, matching, textviews
from llm_vuln_scanner.canary import CanaryFactory
from llm_vuln_scanner.detectors import refusal

pytestmark = pytest.mark.skipif(not _backend.rust_available(), reason="Rust core not built")

# Characters whose Unicode properties agree across Python and Rust Unicode versions.
ALPHABET = st.sampled_from(
    [*list("abcxyzABCXYZ0123456789 -_.,:;/+=!?'\"\n\t`<>{}()$@#"), "\u200b", "\u2060", "\ufeff", "\U000e0041", "\U000e0062", "а", "е", "А", "о", "Ａ", "ｂ", "İ", "é", "ß", "Σ", "\u2014", "½", "①"]
)  # fmt: skip
TEXT = st.text(alphabet=ALPHABET, max_size=80)


def rs():  # type: ignore[no-untyped-def]
    return _backend.rust()


@settings(max_examples=400)
@given(TEXT)
def test_skeleton_parity(s: str) -> None:
    assert rs().skeleton(s) == textviews.skeleton(s)


@settings(max_examples=300)
@given(TEXT)
def test_views_parity(s: str) -> None:
    py = textviews.views(s)
    py["raw"] = py["raw"].lower()
    assert dict(rs().views_of(s)) == py


@pytest.mark.parametrize("kind", sorted(textviews.ENCODERS))
@settings(max_examples=40)
@given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), min_size=1, max_size=40))
def test_encoded_views_parity(kind: str, s: str) -> None:
    enc = textviews.ENCODERS[kind](s)
    py = textviews.views(enc)
    py["raw"] = py["raw"].lower()
    assert dict(rs().views_of(enc)) == py


@settings(max_examples=300)
@given(
    TEXT, st.lists(st.sampled_from(["LVS-7F3A-PELICAN", "ab", "", "x-y-z-1-2-3", "Hello World"]), max_size=4)
)
def test_find_canaries_parity(s: str, canaries: list[str]) -> None:
    for c in canaries[:2]:
        s = s + " " + textviews.ENCODERS["base64"](c) + " " + c[::-1]
    py = matching.find_canaries(s, canaries, backend="python")
    assert matching.find_canaries(s, canaries, backend="rust") == py


def test_find_canaries_batch_matches_single() -> None:
    f = CanaryFactory(5)
    toks = [f.token() for _ in range(20)]
    texts = [f"x {toks[i]} y" if i % 3 else textviews.hexenc(toks[i]) for i in range(20)]
    batch = rs().find_canaries_batch(texts, [toks] * 20)
    assert [list(map(tuple, b)) for b in batch] == [
        matching.find_canaries(t, toks, backend="python") for t in texts
    ]


@settings(max_examples=300)
@given(st.lists(st.sampled_from("abcd"), max_size=150), st.lists(st.sampled_from("abcd"), max_size=150))
def test_lcs_parity(a: list[str], b: list[str]) -> None:
    assert matching.lcs_len(a, b, backend="rust") == matching.lcs_len_py(a, b)


@settings(max_examples=300)
@given(TEXT)
def test_ngram_parity(s: str) -> None:
    py = refusal.ngram_counts_py(s, 18)
    assert refusal.ngram_counts(s, 18, backend="rust") == py


def test_featurize_parity() -> None:
    texts = ["I'm sorry, but I can't help with that.", "", "Sure! Here are the steps.", "a" * 2000]
    a = refusal.featurize(texts, backend="rust")
    b = refusal.featurize(texts, backend="python")
    assert np.array_equal(a.indptr, b.indptr) and np.array_equal(a.indices, b.indices)
    assert np.allclose(a.data, b.data)


def test_backend_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _backend.resolve("auto") == "rust"
    assert _backend.resolve("python") == "python"
    with pytest.raises(ValueError):
        _backend.resolve("gpu")  # type: ignore[arg-type]
