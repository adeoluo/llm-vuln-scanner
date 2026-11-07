//! Rust core of llm-vuln-scanner.
//!
//! - [`views`]: the text views the canary detector searches (skeleton, unleet,
//!   reversed, ROT13, decoded base64, hex and Morse runs);
//! - [`aho`]: an Aho-Corasick automaton for multi-pattern search;
//! - [`canary`]: canary search across all views with one automaton per view;
//! - [`lcs`]: bit-parallel longest common subsequence length over token ids;
//! - [`ngrams`]: hashed character and word n-gram counts for the refusal classifier.
//!
//! Every function has a Python reference implementation in the package, and the parity
//! tests check that both produce the same results.

pub mod aho;
pub mod canary;
pub mod lcs;
pub mod ngrams;
pub mod views;

#[cfg(feature = "python")]
mod python;
