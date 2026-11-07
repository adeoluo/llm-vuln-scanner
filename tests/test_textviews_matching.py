"""Text views, encoders, canary search and LCS similarity."""

from __future__ import annotations

import functools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from llm_vuln_scanner import matching, textviews
from llm_vuln_scanner.canary import CanaryFactory

CANARY = "LVS-7F3A-PELICAN"


def test_canary_factory_is_deterministic_and_unique() -> None:
    a, b = CanaryFactory(3), CanaryFactory(3)
    toks = [a.token() for _ in range(200)]
    assert toks == [b.token() for _ in range(200)]
    assert len(set(toks)) == 200
    assert all(t.startswith("LVS-") for t in toks)
    s = a.secret()
    assert s[0].isupper() and any(c.isdigit() for c in s)
    key_id, secret = a.fake_aws_key()
    assert key_id.startswith("AKIA") and len(key_id) == 20 and len(secret) == 40


@pytest.mark.parametrize("kind", sorted(textviews.ENCODERS))
def test_every_encoding_is_found_by_the_views(kind: str) -> None:
    encoded = textviews.ENCODERS[kind](f"the code is {CANARY}")
    found = matching.find_canaries(encoded, [CANARY], backend="python")
    if kind == "leetspeak":
        # Leetspeak of a token with digits is ambiguous; unleet maps 7->t, 3->e.
        assert found == [] or found[0][0] == 0
    else:
        assert found and found[0][0] == 0


def test_views_names() -> None:
    v = textviews.views("aGVsbG8gd29ybGQgaGVsbG8=")
    assert {"raw", "skeleton", "unleet", "reversed", "rot13", "base64"} <= set(v)
    assert "helloworld" in v["base64"]


def test_skeleton_folds_case_spacing_homoglyphs_and_invisibles() -> None:
    assert textviews.skeleton("L-V-S 7f3a") == "lvs7f3a"
    assert textviews.skeleton("р\u200bа\u200bss") == "pass"
    assert textviews.skeleton(textviews.tag_smuggle("Hi There")) == "hithere"


def test_decoders_ignore_invalid_runs() -> None:
    assert textviews.decode_base64_runs("!!!!$$$$") == []
    assert textviews.decode_base64_runs("////////////////") == []
    assert textviews.decode_hex_runs("zz zz zz") == []
    assert textviews.decode_hex_runs("ff fe fd fc fb fa") == []
    assert textviews.decode_hex_runs("68 65 6c 6c 6f 21") == ["hello!"]


def test_morse_round_trip() -> None:
    assert textviews.decode_morse_runs(textviews.morse("reply with abc123")) == ["reply with abc123"]


@given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), min_size=1, max_size=60))
def test_encoders_round_trip(s: str) -> None:
    assert textviews.strip_invisible(textviews.zero_width(s)) == s
    assert textviews.strip_invisible(textviews.tag_smuggle(s)) == s
    assert textviews.rot13(textviews.rot13(s)) == s
    assert textviews.reverse(textviews.reverse(s)) == s


def test_find_canaries_reports_view_and_ignores_short_skeletons() -> None:
    assert matching.find_canaries(f"Sure: {CANARY}", [CANARY], backend="python") == [(0, "raw")]
    spaced = " ".join(CANARY)
    assert matching.find_canaries(spaced, [CANARY], backend="python") == [(0, "skeleton")]
    assert matching.find_canaries("a b", ["ab"], backend="python") == []
    assert matching.find_canaries("", [CANARY], backend="python") == []
    assert matching.find_canaries("x", [], backend="python") == []
    assert matching.find_canaries("x", [""], backend="python") == []


def test_find_canaries_many_patterns() -> None:
    f = CanaryFactory(1)
    toks = [f.token() for _ in range(50)]
    text = "noise " + toks[7] + " more " + textviews.b64(toks[30])
    found = dict(matching.find_canaries(text, toks, backend="python"))
    assert found == {7: "raw", 30: "base64"}


def lcs_brute(a: list[str], b: list[str]) -> int:

    @functools.cache
    def go(i: int, j: int) -> int:
        if i == len(a) or j == len(b):
            return 0
        if a[i] == b[j]:
            return 1 + go(i + 1, j + 1)
        return max(go(i + 1, j), go(i, j + 1))

    return go(0, 0)


@settings(max_examples=150)
@given(st.lists(st.sampled_from("abcde"), max_size=12), st.lists(st.sampled_from("abcde"), max_size=12))
def test_lcs_matches_brute_force(a: list[str], b: list[str]) -> None:
    assert matching.lcs_len_py(a, b) == lcs_brute(a, b)


def test_leak_ratio() -> None:
    secret = "You are DigestBot. The reference code is LVS-1234-ORCHID."
    assert matching.leak_ratio(secret, secret, backend="python") == 1.0
    assert matching.leak_ratio(secret, "I summarize text.", backend="python") < 0.3
    assert matching.leak_ratio("", "anything", backend="python") == 0.0
    noisy = "Sure! " + secret.replace("The", "Okay the") + " Hope that helps."
    assert matching.leak_ratio(secret, noisy, backend="python") == 1.0
