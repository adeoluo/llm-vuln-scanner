# Evaluation Report: LLM Vuln Scanner

Reproduce every table with `make evaluation` (it prints them from `benchmarks/results/`);
the commands that produce each results file are listed under Reproducibility.

## Setup

- **Hardware:** Apple M1 (8 cores, 8 GB), shared with other work; one heavy job at a time.
- **Targets:**
  - Qwen2.5-0.5B-Instruct via transformers (fp16 on MPS, serialized requests);
  - Qwen2.5-1.5B-Instruct Q4_K_M and SmolLM2-1.7B-Instruct Q4_K_M via llama.cpp
    `llama-server` (4 slots of 4,096 tokens and 2 slots of 2,048 tokens);
  - Qwen2.5-3B-Instruct Q3_K_M via llama.cpp (2 slots of 4,096 tokens; Q3_K_M instead of
    Q4_K_M keeps the server under 2.5 GB of memory);
  - the bundled demo application ("Northwind Kettles support") in vulnerable and hardened
    mode, backed by Qwen2.5-1.5B.
- **Probe set:** the default set of 11 probes (540 attempts against a bare model, 222
  against the demo application through its profile), plus four public datasets on
  Qwen2.5-1.5B: Tensor Trust hijacking and extraction (seeded samples of 300 of 776 and 300
  of 570), Gandalf ignore-instructions (seeded sample of 300 of 1,000) and the usable
  in-the-wild jailbreak templates (all 106).
- **Decoding:** greedy (temperature 0), one generation per attempt, seed 0, per-attempt
  token budgets set by each probe (32 to 512 tokens).
- **Metric:** attack success rate = successes / attempts, with Wilson score 95% intervals;
  differences between two targets use Newcombe's hybrid score interval. Errors are
  counted separately and are zero in every committed run.
- **Graders:** deterministic detectors (canary search, LCS leakage, SQLite sink, HTML parser,
  shell tokenizer, tool-call log, token budget, regex) and, for jailbreaks, the refusal
  classifier (`rule="all"`: the compliance canary and a non-refusal are both required).
  The refusal detectors are validated against human labels (XSTest v2) below.

TABLES

## Threats to validity

- **Small models, one machine.** Rates are for 0.5B to 3B models with greedy decoding;
  larger models and sampled decoding behave differently. Quantization (Q3_K_M, Q4_K_M)
  can change refusal behaviour compared with the fp16 checkpoints.
- **Probe templates are fixed and public.** A model trained on them would score better
  without being safer; the dataset probes (written by other people) partly address this.
- **Detector false negatives.** Canary detectors cannot see a paraphrased secret or a
  jailbreak that complies without the marker, so every rate is a lower bound. The
  detector benchmark measures refusal detection only, not canary recall.
- **Masked credentials.** Committed reports mask credential-shaped strings, so re-scoring
  from the reports instead of the raw response cache would undercount disclosure; the
  ablation script re-scores from the cache and reports 0 mismatches against the stored
  verdicts.
- **garak comparison.** garak and this scanner use different prompts, detectors and
  success definitions; the comparison is about coverage and how often each tool flags the
  same model, not a head-to-head accuracy measurement.
- **A bug found and fixed during evaluation.** The first demo application scans shared
  response-cache keys between attempts that differ only in the attached document, so 104
  of 222 attempts reused another attempt's response. The cache key now covers the
  document (with a regression test) and the committed demo results come from the fixed
  code. Model scans were unaffected (no attempt there carries a separate document).

## Reproducibility

```bash
make bench-setup data models
cd benchmarks
uv run --no-sync python scan_models.py --model qwen2.5-1.5b          # and smollm2-1.7b, qwen2.5-0.5b, qwen2.5-3b
uv run --no-sync python scan_models.py --model demo-vulnerable        # and demo-hardened
uv run --no-sync python scan_models.py --model qwen2.5-1.5b --run qwen2.5-1.5b-datasets --probes dataset --sample 300
uv run --no-sync python detectors.py
uv run --no-sync python garak_compare.py
uv run --no-sync python ablations.py
uv run --no-sync python speed.py
uv run --no-sync python report.py
```

Responses are cached in `../.bench-data/llm-vuln-scanner/cache/`, so each command resumes
after an interruption and re-scoring is free.
