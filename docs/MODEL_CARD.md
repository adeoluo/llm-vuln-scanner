# Model and System Card: LLM Vuln Scanner

## Overview
- **What it is:** a vulnerability scanner for LLM applications. It sends probes (attack
  attempts) to a target, decides success with detectors, and reports findings mapped to
  the OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS.
- **Bundled model:** `refusal-v1`, a logistic regression over 2^18 hashed character and
  word n-grams, trained on the 2,250 human-labelled XSTest v2 completions (0.6 MB).
- **Models scanned in the benchmarks:** Qwen2.5-0.5B-Instruct (transformers, fp16 on MPS),
  Qwen2.5-1.5B-Instruct and SmolLM2-1.7B-Instruct (Q4_K_M GGUF on llama.cpp).
- **Version and date:** 0.1.0, November 2026.

## Intended use
- Pre-deployment and CI regression scanning of LLM endpoints and LLM-backed applications
  that the user owns or is authorized to test.
- Comparing models, prompts and guardrails on the same probe set with confidence intervals.

## Out-of-scope and prohibited use
- Scanning systems without authorization.
- Treating a clean report as proof of security: probes cover known technique families,
  not every attack, and a scanner run is a lower bound on vulnerability.
- Using the refusal classifier as a content-safety filter: it detects refusal style, not harm.

## Performance
See [EVALUATION_REPORT.md](EVALUATION_REPORT.md). In short: the refusal classifier is
roughly as accurate as the keyword list on held-out XSTest answering models, the
canary detectors have a near-zero false-positive rate by construction, and the sink
detectors change the verdict on a measurable share of output handling attempts compared
with regex matching (see the ablation table).

## Risks and limitations
- Detectors miss attacks whose success is not observable as a canary, a tool call or a
  sink effect (for example a paraphrased secret below the 50% LCS threshold).
- Success rates depend on decoding; the benchmarks use greedy decoding and one generation.
- The demo application is deliberately vulnerable; run it on localhost only.

## Safety mitigations
- Fictional canaries and fictional restricted tasks only; no real harmful requests.
- Planted credentials are fake and credential-shaped strings are masked in committed reports.
- Sink detectors never execute output outside an in-memory SQLite fixture with a
  write-denying authorizer; shell output is tokenized, never run.

## Environmental and cost footprint
All benchmarks ran on one Apple M1 laptop (8 GB, 8 cores); a full default scan of a 1.5B
model takes about 25 minutes. No paid API was used.
