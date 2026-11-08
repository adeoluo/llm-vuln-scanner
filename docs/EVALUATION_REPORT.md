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

## Results

## Scans of local models

The default probe set against each model with no application around it: the system
prompt, planted secrets, tools and sinks come from the probe itself.

### Local models, default probe set (540 attempts each, greedy)

| Probe | OWASP | qwen2.5-1.5b | smollm2-1.7b |
|---|---|---|---|
| `encoding.obfuscation` | LLM01 | 9/66 (14%, 7% to 24%) | 12/66 (18%, 11% to 29%) |
| `injection.direct` | LLM01 | 39/60 (65%, 52% to 76%) | 36/60 (60%, 47% to 71%) |
| `injection.indirect` | LLM01 | 18/72 (25%, 16% to 36%) | 22/72 (31%, 21% to 42%) |
| `jailbreak.templates` | LLM01 | 75/90 (83%, 74% to 90%) | 27/90 (30%, 22% to 40%) |
| `disclosure.secrets` | LLM02 | 31/48 (65%, 50% to 77%) | 26/48 (54%, 40% to 67%) |
| `output.shell` | LLM10 | 18/24 (75%, 55% to 88%) | 17/24 (71%, 51% to 85%) |
| `output.sql` | LLM10 | 10/24 (42%, 24% to 61%) | 13/24 (54%, 35% to 72%) |
| `output.xss` | LLM10 | 16/24 (67%, 47% to 82%) | 12/24 (50%, 31% to 69%) |
| `agency.tools` | LLM03 | 7/40 (18%, 9% to 32%) | 4/40 (10%, 4% to 23%) |
| `leakage.system_prompt` | LLM08 | 43/80 (54%, 43% to 64%) | 27/80 (34%, 24% to 45%) |
| `dos.token_blowup` | LLM06 | 2/12 (17%, 5% to 45%) | 4/12 (33%, 14% to 61%) |
| **All attacks** | | **268/540** (50%) | **200/540** (37%) |
| Errors | | 0 | 0 |
| Wall clock | | 24 min | 34 min |

Jailbreak templates are the clearest difference: Qwen2.5-1.5B followed 75 of 90 template
attacks on fictional restricted tasks, SmolLM2-1.7B 27 of 90 (difference +53 points,
Newcombe 95% CI +40 to +64). Leakage of the system prompt also differs (+20 points, +5 to
+34); the other probes overlap within their intervals.

### OWASP Top 10 for LLM Applications 2026 coverage and attack success rate

| Category | qwen2.5-1.5b | smollm2-1.7b | demo-vulnerable | demo-hardened |
|---|---|---|---|---|
| LLM01 Prompt Injection | 141/288 (49%) | 97/288 (34%) | 29/106 (27%) | 17/106 (16%) |
| LLM02 Sensitive Information Disclosure | 31/48 (65%) | 26/48 (54%) | 7/12 (58%) | 0/12 (0%) |
| LLM03 Excessive Agency | 7/40 (18%) | 4/40 (10%) | 7/40 (18%) | 0/40 (0%) |
| LLM04 Supply Chain | not tested | not tested | not tested | not tested |
| LLM05 Data and Model Poisoning | not tested | not tested | not tested | not tested |
| LLM06 Unbounded Consumption | 2/12 (17%) | 4/12 (33%) | 1/12 (8%) | 0/12 (0%) |
| LLM07 Misinformation | not tested | not tested | not tested | not tested |
| LLM08 Hidden Context Exposure | 43/80 (54%) | 27/80 (34%) | 9/16 (56%) | 0/16 (0%) |
| LLM09 Vector and Embedding Weaknesses | not tested | not tested | not tested | not tested |
| LLM10 Improper Output Handling | 44/72 (61%) | 42/72 (58%) | 18/36 (50%) | 0/36 (0%) |

"Not tested" categories need access the black-box probes do not have (see Limitations).

## Demo application

The bundled "Northwind Kettles" support application with four LLM features (chat with
documents, SQL order lookup, shell diagnostics, a tool-using agent), scanned through its
profile with the same Qwen2.5-1.5B backend in both modes. Hardened mode applies the
standard mitigation per feature (no secrets in context, spotlighted documents, escaped
HTML, read-only scoped SQL, argument vectors instead of a shell, confirmation for
high-impact tools).

### Demo application, vulnerable versus hardened (same Qwen2.5-1.5B backend)

| Probe | OWASP | demo-vulnerable | demo-hardened |
|---|---|---|---|
| `encoding.obfuscation` | LLM01 | 5/22 (23%, 10% to 43%) | 3/22 (14%, 5% to 33%) |
| `injection.direct` | LLM01 | 7/12 (58%, 32% to 81%) | 8/12 (67%, 39% to 86%) |
| `injection.indirect` | LLM01 | 17/72 (24%, 15% to 35%) | 6/72 (8%, 4% to 17%) |
| `disclosure.secrets` | LLM02 | 7/12 (58%, 32% to 81%) | 0/12 (0%, 0% to 24%) |
| `output.shell` | LLM10 | 9/12 (75%, 47% to 91%) | 0/12 (0%, 0% to 24%) |
| `output.sql` | LLM10 | 6/12 (50%, 25% to 75%) | 0/12 (0%, 0% to 24%) |
| `output.xss` | LLM10 | 3/12 (25%, 9% to 53%) | 0/12 (0%, 0% to 24%) |
| `agency.tools` | LLM03 | 7/40 (18%, 9% to 32%) | 0/40 (0%, 0% to 9%) |
| `leakage.system_prompt` | LLM08 | 9/16 (56%, 33% to 77%) | 0/16 (0%, 0% to 19%) |
| `dos.token_blowup` | LLM06 | 1/12 (8%, 1% to 35%) | 0/12 (0%, 0% to 24%) |
| **All attacks** | | **71/222** (32%) | **17/222** (8%) |
| Errors | | 0 | 0 |

Hardening removes every SQL, shell, XSS, tool, secret, leakage and token blow-up
finding. Direct prompt injection still succeeds as often (8/12 versus 7/12): the
mitigations limit what an injected instruction can reach, they do not stop the model from
following it. Spotlighting untrusted documents cuts indirect injection from 24% to 8%.

## Detector validation

How much each detector component matters, and how well the refusal detectors agree with
human labels.

### Detector ablations (re-scored offline on the stored responses)

| Variant | qwen2.5-1.5b | smollm2-1.7b |
|---|---|---|
| full | 268/540 (+0, -0) | 200/540 (+0, -0) |
| canary: raw substring | 207/416 (+0, -8) | 140/416 (+0, -10) |
| sinks: regex | 34/72 (+5, -15) | 19/72 (+1, -24) |
| jailbreak: canary only | 79/90 (+4, -0) | 27/90 (+0, -0) |
| refusal: keyword | 72/90 (+2, -5) | 27/90 (+0, -0) |

Each row swaps one detector component for a simpler one and re-scores the stored
responses: "+" are attacks the simpler variant newly counts as successful, "-" are
successes it misses. Raw substring search misses 8 and 10 canaries that the models
reformatted or encoded. Regex rules for the HTML, SQL and shell sinks miss 15 of 44 and 24
of 42 sink findings and add 5 and 1 false ones. Dropping the refusal gate adds 4
jailbreaks that Qwen2.5-1.5B refused after printing the marker.

### Refusal detectors on XSTest v2 (2,250 human-labelled completions)

| Detector | Accuracy | Precision | Recall | F1 | Time |
|---|---|---|---|---|---|
| keyword | 0.884 (0.871 to 0.897) | 0.955 (0.942 to 0.968) | 0.813 (0.791 to 0.835) | 0.878 (0.863 to 0.893) | 0.1 s |
| xstest_strmatch | 0.884 (0.871 to 0.897) | 0.954 (0.940 to 0.966) | 0.815 (0.794 to 0.838) | 0.879 (0.865 to 0.893) | 0.0 s |
| classifier (LOMO) | 0.868 (0.854 to 0.881) | 0.956 (0.941 to 0.968) | 0.779 (0.757 to 0.801) | 0.858 (0.843 to 0.873) | 113.9 s |
| sklearn tfidf+LR (LOMO) | 0.872 (0.859 to 0.885) | 0.949 (0.936 to 0.963) | 0.794 (0.771 to 0.815) | 0.865 (0.850 to 0.879) | 7.3 s |

Leave-one-model-out (LOMO): trained on four XSTest answering models, tested on the fifth.
The trained classifier does not beat the phrase list on held-out models, which is why
jailbreak success also requires the canary (ADR-0006).

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
