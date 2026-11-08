//! PyO3 bindings, built by maturin into the `llm_vuln_scanner.lvs_rs` module.

use pyo3::prelude::*;
use rayon::prelude::*;

use crate::canary;
use crate::lcs;
use crate::ngrams;
use crate::views;

/// `(canary index, view name)` for each canary in `text`.
#[pyfunction]
fn find_canaries(py: Python<'_>, text: &str, canaries: Vec<String>) -> Vec<(usize, &'static str)> {
    py.detach(|| canary::find_canaries(text, &canaries))
}

/// `find_canaries` over many texts in parallel (one canary list per text).
#[pyfunction]
fn find_canaries_batch(
    py: Python<'_>,
    texts: Vec<String>,
    canaries: Vec<Vec<String>>,
) -> Vec<Vec<(usize, &'static str)>> {
    py.detach(|| {
        texts
            .par_iter()
            .zip(canaries.par_iter())
            .map(|(t, c)| canary::find_canaries(t, c))
            .collect()
    })
}

/// Longest common subsequence length of two token lists.
#[pyfunction]
fn lcs_len(py: Python<'_>, a: Vec<String>, b: Vec<String>) -> usize {
    py.detach(|| lcs::lcs_len(&a, &b))
}

/// Sorted `(buckets, counts)` of the hashed n-grams of normalized text.
#[pyfunction]
fn ngram_counts(py: Python<'_>, text: &str, dim_bits: u32) -> (Vec<u32>, Vec<u32>) {
    py.detach(|| ngrams::ngram_counts(text, dim_bits))
}

/// `ngram_counts` over many normalized texts in parallel.
#[pyfunction]
fn ngram_counts_batch(
    py: Python<'_>,
    texts: Vec<String>,
    dim_bits: u32,
) -> Vec<(Vec<u32>, Vec<u32>)> {
    py.detach(|| {
        texts
            .par_iter()
            .map(|t| ngrams::ngram_counts(t, dim_bits))
            .collect()
    })
}

/// Skeleton view (parity tests).
#[pyfunction]
fn skeleton(text: &str) -> String {
    views::skeleton(text)
}

/// All views by name (parity tests); decoded views without a run are omitted.
#[pyfunction]
fn views_of(text: &str) -> Vec<(&'static str, String)> {
    views::VIEW_ORDER
        .iter()
        .zip(views::views(text))
        .filter_map(|(name, v)| v.map(|s| (*name, s)))
        .collect()
}

#[pymodule]
fn lvs_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(find_canaries, m)?)?;
    m.add_function(wrap_pyfunction!(find_canaries_batch, m)?)?;
    m.add_function(wrap_pyfunction!(lcs_len, m)?)?;
    m.add_function(wrap_pyfunction!(ngram_counts, m)?)?;
    m.add_function(wrap_pyfunction!(ngram_counts_batch, m)?)?;
    m.add_function(wrap_pyfunction!(skeleton, m)?)?;
    m.add_function(wrap_pyfunction!(views_of, m)?)?;
    Ok(())
}
