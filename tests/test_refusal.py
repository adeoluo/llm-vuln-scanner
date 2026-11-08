"""The hashed n-gram refusal model: features, training, persistence, scikit-learn parity."""

from __future__ import annotations

import io

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from llm_vuln_scanner.detectors import refusal
from llm_vuln_scanner.detectors.refusal import RefusalModel, featurize, fnv1a, ngram_counts_py

REFUSALS = [
    "I'm sorry, but I can't help with that request.",
    "I cannot provide that information.",
    "As an AI, I am not able to share those details.",
    "Sorry, I won't do that.",
    "I must decline to answer.",
    "I can't assist with this, but I can help with something else.",
]
ANSWERS = [
    "Sure! Here are the steps: first open the menu, then choose settings.",
    "The capital of France is Paris.",
    "Absolutely, here is a short poem about the sea.",
    "To kill a Python process, run kill with its PID.",
    "Here's the summary you asked for: the meeting moved to Tuesday.",
    "Yes. The answer is 42 because six times seven is forty-two.",
]


def test_fnv1a_known_vectors() -> None:
    # Published FNV-1a 32-bit test vectors.
    assert fnv1a(b"") == 0x811C9DC5
    assert fnv1a(b"a") == 0xE40C292C
    assert fnv1a(b"foobar") == 0xBF9CF968


@settings(max_examples=100)
@given(st.text(max_size=200))
def test_features_are_unit_norm_and_in_range(text: str) -> None:
    x = featurize([text], dim_bits=12, backend="python")
    assert x.rows == 1
    if x.data.size:
        assert np.isclose(np.linalg.norm(x.data), 1.0)
        assert x.indices.min() >= 0 and x.indices.max() < 1 << 12


def test_counts_are_case_and_contraction_insensitive() -> None:
    assert ngram_counts_py("I can't do THAT") == ngram_counts_py("i cannot do that")


def test_empty_text_gives_empty_row() -> None:
    x = featurize(["", "hello world"], dim_bits=10)
    assert x.indptr[1] == 0 and x.rows == 2
    assert x.dot(np.ones(x.dim))[0] == 0.0


def test_csr_matches_dense() -> None:
    texts = REFUSALS + ANSWERS
    x = featurize(texts, dim_bits=10)
    dense = np.zeros((x.rows, x.dim))
    for r in range(x.rows):
        dense[r, x.indices[x.indptr[r] : x.indptr[r + 1]]] += x.data[x.indptr[r] : x.indptr[r + 1]]
    rng = np.random.default_rng(0)
    w, g = rng.normal(size=x.dim), rng.normal(size=x.rows)
    assert np.allclose(x.dot(w), dense @ w)
    assert np.allclose(x.tdot(g), dense.T @ g)


def test_fit_separates_toy_data_and_round_trips(tmp_path: object) -> None:
    texts = REFUSALS + ANSWERS
    y = [1] * len(REFUSALS) + [0] * len(ANSWERS)
    m = RefusalModel.fit(texts, y, dim_bits=14, epochs=200)
    p = m.predict_proba(texts)
    assert ((p >= 0.5).astype(int) == np.asarray(y)).all()
    buf = io.BytesIO()
    m.save(buf)  # type: ignore[arg-type]
    buf.seek(0)
    m2 = RefusalModel.load(buf)
    assert np.allclose(m2.predict_proba(texts), p, atol=1e-5)


@pytest.mark.parametrize(("texts", "labels"), [([], []), (["a"], [1, 0]), (["a", "b"], [0, 2])])
def test_fit_rejects_bad_input(texts: list[str], labels: list[int]) -> None:
    with pytest.raises(ValueError):
        RefusalModel.fit(texts, labels)


def test_weights_must_match_dimension() -> None:
    with pytest.raises(ValueError, match="dimension"):
        RefusalModel(np.zeros(5), 0.0, dim_bits=4)


def test_bundled_model_flags_clear_cases() -> None:
    m = RefusalModel.load_default()
    p = m.predict_proba(
        ["I'm sorry, but I cannot help with that.", "Sure, here is the recipe: mix flour and water."]
    )
    assert p[0] > 0.5 > p[1]


@pytest.mark.validation
def test_gradient_descent_matches_sklearn_logistic_regression() -> None:
    """Same convex objective, so the same optimum as scikit-learn's L-BFGS solver."""
    sk = pytest.importorskip("sklearn.linear_model")
    sp = pytest.importorskip("scipy.sparse")
    texts = REFUSALS + ANSWERS
    y = np.asarray([1] * len(REFUSALS) + [0] * len(ANSWERS))
    l2 = 1e-2
    ours = RefusalModel.fit(texts, list(y), l2=l2, epochs=3000, lr=2.0, dim_bits=12)
    x = featurize(texts, dim_bits=12)
    xm = sp.csr_matrix((x.data, x.indices, x.indptr), shape=(x.rows, x.dim))
    # sklearn minimizes C * sum(loss) + 0.5 ||w||^2; ours mean(loss) + 0.5 l2 ||w||^2.
    ref = sk.LogisticRegression(C=1.0 / (l2 * len(y)), tol=1e-10, max_iter=10_000).fit(xm, y)
    assert np.allclose(ours.predict_proba(texts), ref.predict_proba(xm)[:, 1], atol=2e-3)
    assert np.allclose(ours.w[np.unique(x.indices)], ref.coef_[0][np.unique(x.indices)], atol=2e-2)


def test_refusal_module_exports_detectors() -> None:
    assert refusal.RefusalClassifierDetector().name == "refusal_classifier"
