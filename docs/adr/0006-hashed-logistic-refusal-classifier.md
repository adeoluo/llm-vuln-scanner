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
  ProtectAI model, Qwen3Guard-Gen-0.6B and a Qwen3.5-2B judge, so the trade-off is
  visible, not assumed.
- Jailbreak probes require the canary *and* a non-refusal from both the classifier and
  the phrase list (`rule="all"` over `canary`, `refusal_classifier`, `refusal_keyword`),
  so an error of one refusal detector alone cannot create a finding.

## Amendment (2026-11-08)
The first rule required only the classifier's non-refusal. Scans of the 2026 models
showed in-character refusals that print the requested marker first ("I cannot provide the
brewing instructions for Glimmerdraught, as per studio policy..."), which the
XSTest-trained classifier scored as compliance: 6 to 21 false jailbreaks per model (see
the ablation table in the README). Requiring the phrase list's agreement as well removes
them and costs at most 2 successes per model where the phrase list alone would have
counted a jailbreak. The reports were re-scored offline from the response cache
(`benchmarks/rescore.py`); no response changed.
