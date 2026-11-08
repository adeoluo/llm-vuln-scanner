# ADR-0006: A hashed n-gram logistic regression as the default refusal classifier

- **Status:** Accepted
- **Date:** 2026-11-07

## Context
Jailbreak success needs a refusal decision for every response. Options: a phrase list,
a fine-tuned transformer (for example ProtectAI distilroberta-base-rejection-v1, 82M
parameters, 330 MB), or an LLM judge. The scanner must stay installable without PyTorch,
run in CI and in a GitHub Action, and score thousands of responses per second.

## Decision
Ship a logistic regression over hashed character 3 to 5 grams and word n-grams (2^18
buckets, FNV-1a, Rust featurizer) trained on the 2,250 human-labelled XSTest v2
completions, stored as a 0.6 MB sparse `.npz`. Keep the keyword detector, and offer the
LLM judge as an opt-in detector for any OpenAI-compatible or local model.

## Consequences
- No heavy dependency; scoring is microseconds per response.
- On held-out answering models (leave one model out) it does not beat the phrase list on
  XSTest; benchmarks/detectors.py reports every detector side by side, including the
  ProtectAI model and a Qwen2.5-1.5B judge, so the trade-off is visible, not assumed.
- Jailbreak probes require the canary *and* a classifier non-refusal (`rule="all"`), so a
  classifier error alone cannot create a finding.
