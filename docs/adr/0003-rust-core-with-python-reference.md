# ADR-0003: Rust core for detector hot loops, Python reference kept for parity

- **Status:** Accepted
- **Date:** 2026-11-07

## Context
Detectors run on every response, and dataset probes and re-scoring runs multiply that by
thousands. Three kernels dominate: building the normalized text views and searching them
for many canaries, the token LCS between a system prompt and an output, and hashing
character and word n-grams for the refusal classifier. In Python these are loops over
characters and an O(nm) dynamic program.

## Decision
Implement the three kernels in a Rust crate (`rust/`) compiled into the package with
PyO3 and maturin as `llm_vuln_scanner.lvs_rs` (abi3 wheels):

- one Aho-Corasick automaton over all canary patterns per view (linear in text length);
- bit-parallel LCS length (Allison and Dix 1986, Hyyro 2004): O(ceil(m/64) n) word
  operations;
- FNV-1a hashed n-gram counts identical to the Python reference, bucket for bucket.

Every function has a Python reference implementation; `backend="auto"` uses Rust when the
extension is importable, `LVS_REQUIRE_RUST=1` makes a missing build an error in CI, and
property-based tests (hypothesis) assert identical outputs on random Unicode text.

## Consequences
- The measured speedups are in benchmarks/results/speed.json (README "Results").
- A Rust toolchain is needed to build from source; wheels remove that for users.
- Unicode handling must agree across Python and Rust; the parity tests pin it, and the
  test alphabet avoids code points whose properties changed between Unicode versions.
