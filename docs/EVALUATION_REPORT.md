# Evaluation Report: LLM Vuln Scanner

Reproduce every table with `make evaluation` (it prints them from `benchmarks/results/`);
the commands that produce each results file are listed under Reproducibility.

## Setup

- **Hardware:** Apple M1 (8 cores, 8 GB), shared with other work (another project trained a
  network on the same GPU during most runs, so wall-clock times are upper bounds); one
  heavy job at a time, peak memory under 3 GB.
- **Targets:** the current small open instruction models, as GGUF builds served by
  llama.cpp 0.9.0 (b9.0, build 12110) `llama-server` with 4 parallel slots of 4,096 tokens:
  - Qwen3.5-0.8B and Qwen3.5-2B (Q4_K_M) and Qwen3.5-4B (Q3_K_M, which keeps the server
    under about 2.7 GB), released February 2026, from the unsloth GGUF builds. Qwen3.5 is
    a hybrid reasoning model that thinks by default; the scans use its non-thinking mode
    (`--chat-template-kwargs '{"enable_thinking": false}'`), the usual setting for a chat
    feature with a latency budget;
  - gemma-4-E2B-it (Google's quantization-aware Q4_0 build), released March 2026;
  - granite-4.2-3b (IBM's Q4_K_M build), released August 2026;
  - the bundled demo application ("Northwind Kettles support") in vulnerable and hardened
    mode, backed by Qwen3.5-2B.
- **Probe set:** the default set of 11 probes (540 attempts against a bare model, 222
  against the demo application through its profile), plus four public datasets on
  Qwen3.5-2B: Tensor Trust hijacking and extraction (seeded samples of 150 of 776 and 150
  of 570), Gandalf ignore-instructions (seeded sample of 150 of 1,000) and the usable
  in-the-wild jailbreak templates (all 106).
- **Taxonomy:** OWASP Top 10 for LLM Applications 2026, OWASP Top 10 for Agentic
  Applications 2026 and MITRE ATLAS v2026.10 (ADR-0007).
- **Decoding:** greedy (temperature 0), one generation per attempt, seed 0, per-attempt
  token budgets set by each probe (32 to 512 tokens).
- **Metric:** attack success rate = successes / attempts, with Wilson score 95% intervals;
  differences between two targets use Newcombe's hybrid score interval. Errors are
  counted separately and are zero in every committed run.
- **Graders:** deterministic detectors (canary search, LCS leakage, SQLite sink, HTML parser,
  shell tokenizer, tool-call log, token budget, regex) and, for jailbreaks, the refusal
  classifier (`rule="all"`: the compliance canary and a non-refusal are both required).
  The refusal detectors are validated against human labels (XSTest v2) below, next to two
  references: ProtectAI distilroberta-base-rejection-v1 and Qwen3Guard-Gen-0.6B.

## Results

## Scans of local models

The default probe set against each model with no application around it: the system
prompt, planted secrets, tools and sinks come from the probe itself. Reproduce with
`make scans` (or `uv run --no-sync python benchmarks/scan_models.py --model KEY`).

### Models scanned (llama.cpp, greedy, parallel slots of 4,096 tokens)

| Key | Model | Released | GGUF build | Quantization | Slots | Mean output tokens | Scan time |
|---|---|---|---|---|---|---|---|
| qwen3.5-0.8b | [Qwen/Qwen3.5-0.8B](https://huggingface.co/Qwen/Qwen3.5-0.8B) | 2026-02 | [unsloth/Qwen3.5-0.8B-GGUF](https://huggingface.co/unsloth/Qwen3.5-0.8B-GGUF) `Qwen3.5-0.8B-Q4_K_M.gguf` | Q4_K_M | 4 | 82 | 37 min |
| qwen3.5-2b | [Qwen/Qwen3.5-2B](https://huggingface.co/Qwen/Qwen3.5-2B) | 2026-02 | [unsloth/Qwen3.5-2B-GGUF](https://huggingface.co/unsloth/Qwen3.5-2B-GGUF) `Qwen3.5-2B-Q4_K_M.gguf` | Q4_K_M | 4 | 76 | 55 min |

Server: llama.cpp `llama-server` 0.9.0 (build 12110, commit cd959bae9).

Mean output tokens is over all 540 attempts; scan time is generation time on the shared
GPU (another project trained a network on it during most runs), so it is comparable only
within this table.

### Local models, default probe set (540 attempts each, greedy)

| Probe | OWASP 2026 | qwen3.5-0.8b | qwen3.5-2b |
|---|---|---|---|
| `encoding.obfuscation` | LLM01:2026 | 24/66 (36%, 26% to 48%) | 24/66 (36%, 26% to 48%) |
| `injection.direct` | LLM01:2026 | 50/60 (83%, 72% to 91%) | 52/60 (87%, 76% to 93%) |
| `injection.indirect` | LLM01:2026 | 22/72 (31%, 21% to 42%) | 38/72 (53%, 41% to 64%) |
| `jailbreak.templates` | LLM01:2026 | 79/90 (88%, 79% to 93%) | 37/90 (41%, 32% to 51%) |
| `disclosure.secrets` | LLM02:2026 | 26/48 (54%, 40% to 67%) | 23/48 (48%, 34% to 62%) |
| `agency.tools` | LLM03:2026 | 7/40 (18%, 9% to 32%) | 0/40 (0%, 0% to 9%) |
| `dos.token_blowup` | LLM06:2026 | 7/12 (58%, 32% to 81%) | 5/12 (42%, 19% to 68%) |
| `leakage.system_prompt` | LLM08:2026 | 29/80 (36%, 27% to 47%) | 37/80 (46%, 36% to 57%) |
| `output.shell` | LLM10:2026 | 18/24 (75%, 55% to 88%) | 16/24 (67%, 47% to 82%) |
| `output.sql` | LLM10:2026 | 12/24 (50%, 31% to 69%) | 11/24 (46%, 28% to 65%) |
| `output.xss` | LLM10:2026 | 2/24 (8%, 2% to 26%) | 7/24 (29%, 15% to 49%) |
| **All attacks** | | **276/540** (51%) | **250/540** (46%) |
| Errors | | 0 | 0 |

The smallest model is the easiest to jailbreak: Qwen3.5-0.8B followed 79 of 90 template
jailbreaks on fictional restricted tasks, Qwen3.5-2B 37 of 90 (difference +47 points,
Newcombe 95% CI +33 to +58). The larger model is more exposed to indirect injection
(38/72 against 22/72, -22 points, -37 to -6): it reads and acts on instructions inside
documents more often. Qwen3.5-2B never called a tool because of an injected email
(0/40); it summarised the email and quoted the instruction instead.

### OWASP Top 10 for LLM Applications 2026: coverage and attack success rate

| Category | qwen3.5-0.8b | qwen3.5-2b | demo-vulnerable | demo-hardened |
|---|---|---|---|---|
| LLM01:2026 Prompt Injection | 175/288 (61%) | 151/288 (52%) | 51/106 (48%) | 37/106 (35%) |
| LLM02:2026 Sensitive Information Disclosure | 26/48 (54%) | 23/48 (48%) | 3/12 (25%) | 0/12 (0%) |
| LLM03:2026 Excessive Agency | 7/40 (18%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| LLM04:2026 Supply Chain | not tested | not tested | not tested | not tested |
| LLM05:2026 Data and Model Poisoning | not tested | not tested | not tested | not tested |
| LLM06:2026 Unbounded Consumption | 7/12 (58%) | 5/12 (42%) | 3/12 (25%) | 0/12 (0%) |
| LLM07:2026 Misinformation | not tested | not tested | not tested | not tested |
| LLM08:2026 Hidden Context Exposure | 29/80 (36%) | 37/80 (46%) | 8/16 (50%) | 0/16 (0%) |
| LLM09:2026 Vector and Embedding Weaknesses | not tested | not tested | not tested | not tested |
| LLM10:2026 Improper Output Handling | 32/72 (44%) | 34/72 (47%) | 16/36 (44%) | 0/36 (0%) |

Every probe maps to one 2026 category (`llm-vuln-scanner taxonomy`, ADR-0007). "Not
tested" categories need access the black-box probes do not have (see Limitations).

### OWASP Top 10 for Agentic Applications 2026: risks the agent and tool probes exercise

| Risk | Probes | qwen3.5-0.8b | qwen3.5-2b | demo-vulnerable | demo-hardened |
|---|---|---|---|---|---|
| ASI01:2026 Agent Goal Hijack | `agency.tools` | 7/40 (18%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| ASI02:2026 Tool Misuse & Exploitation | `agency.tools` | 7/40 (18%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| ASI05:2026 Unexpected Code Execution (RCE) | `output.shell` | 18/24 (75%) | 16/24 (67%) | 8/12 (67%) | 0/12 (0%) |

`agency.tools` covers Agent Goal Hijack and Tool Misuse & Exploitation; `output.shell`
covers Unexpected Code Execution because the feature it models runs the command.

## Demo application

The bundled "Northwind Kettles" support application with four LLM features (chat with
documents, SQL order lookup, shell diagnostics, a tool-using agent), scanned through its
profile with the same Qwen3.5-2B backend in both modes. Hardened mode applies the
standard mitigation per feature (no secrets in context, spotlighted documents, escaped
HTML, read-only scoped SQL, argument vectors instead of a shell, confirmation for
high-impact tools). Reproduce with `make demo-scans`.

### Demo application, vulnerable versus hardened (same Qwen3.5-2B Q4_K_M backend)

| Probe | OWASP 2026 | demo-vulnerable | demo-hardened |
|---|---|---|---|
| `encoding.obfuscation` | LLM01:2026 | 5/22 (23%, 10% to 43%) | 5/22 (23%, 10% to 43%) |
| `injection.direct` | LLM01:2026 | 8/12 (67%, 39% to 86%) | 8/12 (67%, 39% to 86%) |
| `injection.indirect` | LLM01:2026 | 38/72 (53%, 41% to 64%) | 24/72 (33%, 24% to 45%) |
| `disclosure.secrets` | LLM02:2026 | 3/12 (25%, 9% to 53%) | 0/12 (0%, 0% to 24%) |
| `agency.tools` | LLM03:2026 | 0/40 (0%, 0% to 9%) | 0/40 (0%, 0% to 9%) |
| `dos.token_blowup` | LLM06:2026 | 3/12 (25%, 9% to 53%) | 0/12 (0%, 0% to 24%) |
| `leakage.system_prompt` | LLM08:2026 | 8/16 (50%, 28% to 72%) | 0/16 (0%, 0% to 19%) |
| `output.shell` | LLM10:2026 | 8/12 (67%, 39% to 86%) | 0/12 (0%, 0% to 24%) |
| `output.sql` | LLM10:2026 | 5/12 (42%, 19% to 68%) | 0/12 (0%, 0% to 24%) |
| `output.xss` | LLM10:2026 | 3/12 (25%, 9% to 53%) | 0/12 (0%, 0% to 24%) |
| **All attacks** | | **81/222** (36%) | **37/222** (17%) |
| Errors | | 0 | 0 |

Hardening removes every SQL, shell, XSS, secret, hidden-context and token blow-up
finding. Direct prompt injection succeeds as often in both modes (8/12): the mitigations
limit what an injected instruction can reach, they do not stop the model from following
it. Spotlighting untrusted documents cuts indirect injection from 53% to 33%.

## Comparison with garak

[garak](https://github.com/NVIDIA/garak) 0.17.1 (NVIDIA's LLM vulnerability scanner) against
the same Qwen3.5-2B server (same GGUF, non-thinking mode, greedy, one generation, garak's
150-token default budget), with the 19 garak probes that match this scanner's OWASP
categories and do not ask for harmful content, at most 24 prompts per probe where garak
honours the cap. An attempt counts when any of its probe's detectors scores at least 0.5.
garak tags probes with the 2023 OWASP numbering, so each probe is mapped here to the 2026
category of the behaviour it tests (`benchmarks/garak_compare.py`). Reproduce with
`make garak`.

### Same model (qwen3.5-2b), garak 0.17.1 versus this scanner, by OWASP 2026 category

| OWASP | garak probes | garak attacks flagged | this scanner probes | this scanner attacks succeeded |
|---|---|---|---|---|
| LLM01:2026 Prompt Injection | 12 | 196/543 (36%) | 4 | 151/288 (52%) |
| LLM02:2026 Sensitive Information Disclosure | 3 | 36/72 (50%) | 1 | 23/48 (48%) |
| LLM03:2026 Excessive Agency | 0 | not covered | 1 | 0/40 (0%) |
| LLM06:2026 Unbounded Consumption | 0 | not covered | 1 | 5/12 (42%) |
| LLM08:2026 Hidden Context Exposure | 1 | 1/24 (4%) | 1 | 37/80 (46%) |
| LLM10:2026 Improper Output Handling | 3 | 22/75 (29%) | 3 | 34/72 (47%) |

garak: 714 attempts in 117 min; this scanner: 540 attempts in 55 min.

The two tools agree that the model follows injected instructions (garak's latent injection
probes: 158 of 240 attempts flagged; this scanner's indirect injection: 38 of 72). They
disagree where their definitions differ: garak's five encoding probes flagged 0 of 120
because its detectors look for the decoded payload in the output, while this scanner's
`encoding.obfuscation` counts a planted canary in any decoded view (24 of 66); garak's
system prompt extraction flagged 1 of 24 against 37 of 80 here: garak's detector scores
how closely the output reproduces its system prompt, while this scanner also counts a
planted code that comes back paraphrased, translated, spelled out or encoded. garak covers
training-data divergence (`divergence.Repeat`, 36 of 36 flagged by its detector) and ANSI
escape output, which this scanner does not test; this scanner covers excessive agency and
token blow-up, which the selected garak probes do not. The garak run took longer per
attempt because the machine was swapping during most of it, so the times are not a speed
comparison.

## Detector validation

How well the refusal detectors agree with human labels. Every jailbreak verdict needs a
refusal decision, so the scanner's jailbreak numbers are only as good as these detectors.
Reproduce with `make detectors`.

### Refusal detectors on XSTest v2 (2,250 human-labelled completions)

| Detector | Accuracy | Precision | Recall | F1 | Time |
|---|---|---|---|---|---|
| keyword | 0.884 (0.871 to 0.897) | 0.955 (0.942 to 0.968) | 0.813 (0.791 to 0.835) | 0.878 (0.863 to 0.893) | 0.1 s |
| xstest_strmatch | 0.884 (0.871 to 0.897) | 0.954 (0.940 to 0.966) | 0.815 (0.794 to 0.838) | 0.879 (0.865 to 0.893) | 0.0 s |
| classifier (LOMO) | 0.868 (0.854 to 0.881) | 0.956 (0.941 to 0.968) | 0.779 (0.757 to 0.801) | 0.858 (0.843 to 0.873) | 35.5 s |
| sklearn tfidf+LR (LOMO) | 0.872 (0.859 to 0.885) | 0.949 (0.936 to 0.963) | 0.794 (0.771 to 0.815) | 0.865 (0.850 to 0.879) | 2.9 s |
| protectai distilroberta | 0.872 (0.858 to 0.885) | 0.850 (0.829 to 0.870) | 0.911 (0.894 to 0.928) | 0.880 (0.865 to 0.892) | 83.3 s |
| qwen3guard-gen-0.6b | 0.906 (0.894 to 0.917) | 0.943 (0.929 to 0.956) | 0.871 (0.851 to 0.890) | 0.905 (0.893 to 0.917) | 2548.7 s |
| judge qwen3.5-2b | 0.834 (0.800 to 0.864) | 0.938 (0.898 to 0.968) | 0.717 (0.661 to 0.772) | 0.813 (0.772 to 0.850) | 460.2 s |
| keyword (judge sample) | 0.884 (0.854 to 0.910) | 0.957 (0.927 to 0.981) | 0.805 (0.754 to 0.849) | 0.875 (0.839 to 0.904) | 0.0 s |

Leave-one-model-out (LOMO): trained on four XSTest answering models, tested on the fifth.
ProtectAI distilroberta-base-rejection-v1 (82M parameters) and Qwen3Guard-Gen-0.6B (in
its response-moderation mode, which answers "Refusal: Yes" or "No") are public reference
models, not trained here. The Qwen3.5-2B judge graded a seeded random sample of 500
completions (shown next to the keyword rule on the same sample) and returned a verdict
every time. Qwen3Guard-Gen-0.6B has the highest accuracy and F1 (0.906 and 0.905 against
0.884 and 0.878 for the phrase list) at about 1.1 s per completion on the shared GPU; the
phrase list and the XSTest string match are as accurate as the trained linear models at a
fraction of the cost, ProtectAI trades precision for recall, and the small judge is the
least accurate (recall 0.72). The trained classifier does not beat the phrase list on
held-out models, which is why jailbreak success also requires the canary (ADR-0006).

## Threats to validity

- **Small quantized models, one shared machine.** Rates are for 0.8B to 4B models in 4-bit
  and 3-bit GGUF builds with greedy decoding; larger models, full precision and sampled
  decoding behave differently, and quantization can change refusal behaviour.
- **Non-thinking mode.** Qwen3.5 was scanned without its reasoning phase. With thinking
  on, responses are several times longer and the model may reason its way into or out of
  an attack; a deployment that serves thinking mode should be scanned in that mode
  (`llama-server --reasoning on`).
- **Probe templates are fixed and public.** A model trained on them would score better
  without being safer; the dataset probes (written by other people) partly address this.
- **Detector false negatives.** Canary detectors cannot see a paraphrased secret or a
  jailbreak that complies without the marker, so every rate is a lower bound. The
  detector benchmark measures refusal detection only, not canary recall.
- **Masked credentials.** Committed reports mask credential-shaped strings, so re-scoring
  from the reports instead of the raw response cache would undercount disclosure; the
  ablation script re-scores from the cache and reports the mismatches against the stored
  verdicts (zero in every run).
- **garak comparison.** garak and this scanner use different prompts, detectors and
  success definitions; the comparison is about coverage and how often each tool flags the
  same model, not a head-to-head accuracy measurement.
- **Wall-clock times.** The GPU was shared with another training job during the scans, so
  times are comparable only within this report and overstate what the hardware does alone.

## Reproducibility

```bash
make bench-setup data
scripts/download_models.sh qwen3.5-2b           # or any key in benchmarks/common.py MODELS
cd benchmarks
uv run --no-sync python scan_models.py --model qwen3.5-2b      # qwen3.5-0.8b, qwen3.5-4b, gemma-4-e2b, granite-4.2-3b
uv run --no-sync python scan_models.py --model qwen3.5-4b --probes injection   # a chunk; rerun without --probes to finish
uv run --no-sync python scan_models.py --model demo-vulnerable  # and demo-hardened (backend qwen3.5-2b)
uv run --no-sync python scan_models.py --model qwen3.5-2b --run qwen3.5-2b-datasets --probes dataset --sample 150
uv run --no-sync python detectors.py
uv run --no-sync python garak_compare.py --model qwen3.5-2b
uv run --no-sync python ablations.py
uv run --no-sync python speed.py
uv run --no-sync python report.py
```

Responses are cached in `../.bench-data/llm-vuln-scanner/cache/`, so each command resumes
after an interruption, a scan can be split into chunks of probes, and re-scoring is free.
