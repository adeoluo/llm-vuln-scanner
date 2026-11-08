# Evaluation Report: LLM Vuln Scanner

Reproduce every table with `make evaluation` (it prints them from `benchmarks/results/`);
the commands that produce each results file are listed under Reproducibility.

## Setup

- **Hardware:** Apple M1 (8 cores, 8 GB), shared with other work (another project trained a
  network on the same GPU during most runs, so wall-clock times are upper bounds); one
  heavy job at a time, peak memory under 3 GB.
- **Targets:** the current small open instruction models, as GGUF builds served by
  llama.cpp 0.9.0 (b9.0, build 12110) `llama-server` with 2 or 4 parallel slots of 4,096 tokens (per model in the first table):
  - Qwen3.5-0.8B and Qwen3.5-2B (Q4_K_M) and Qwen3.5-4B (Q3_K_M, about 2.9 GB of server
    memory with 4 slots; it continued with 2 slots when the machine started swapping),
    released February 2026, from the unsloth GGUF builds. Qwen3.5 is
    a hybrid reasoning model that thinks by default; the scans use its non-thinking mode
    (`--chat-template-kwargs '{"enable_thinking": false}'`), the usual setting for a chat
    feature with a latency budget;
  - gemma-4-E2B-it (Google's quantization-aware Q4_0 build), released March 2026, and
    granite-4.2-3b (IBM's Q4_K_M build), released August 2026, both with
    `llama-server --reasoning off` and 2 slots. Gemma 4 also thinks by default under
    llama.cpp; a first run in that mode spent most of each token budget on hidden
    reasoning (empty answers cut at the budget) and was discarded;
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

| Key | Model | Released | GGUF build | Quantization | Thinking off | Slots | Mean output tokens | Scan time |
|---|---|---|---|---|---|---|---|---|
| qwen3.5-0.8b | [Qwen/Qwen3.5-0.8B](https://huggingface.co/Qwen/Qwen3.5-0.8B) | 2026-02 | [unsloth/Qwen3.5-0.8B-GGUF](https://huggingface.co/unsloth/Qwen3.5-0.8B-GGUF) `Qwen3.5-0.8B-Q4_K_M.gguf` | Q4_K_M | `enable_thinking: false` | 4 | 82 | 37 min |
| qwen3.5-2b | [Qwen/Qwen3.5-2B](https://huggingface.co/Qwen/Qwen3.5-2B) | 2026-02 | [unsloth/Qwen3.5-2B-GGUF](https://huggingface.co/unsloth/Qwen3.5-2B-GGUF) `Qwen3.5-2B-Q4_K_M.gguf` | Q4_K_M | `enable_thinking: false` | 4 | 76 | 55 min |
| qwen3.5-4b | [Qwen/Qwen3.5-4B](https://huggingface.co/Qwen/Qwen3.5-4B) | 2026-02 | [unsloth/Qwen3.5-4B-GGUF](https://huggingface.co/unsloth/Qwen3.5-4B-GGUF) `Qwen3.5-4B-Q3_K_M.gguf` | Q3_K_M | `enable_thinking: false` | 4 then 2 | 70 | 85 min |
| gemma-4-e2b | [google/gemma-4-E2B-it](https://huggingface.co/google/gemma-4-E2B-it) | 2026-03 | [google/gemma-4-E2B-it-qat-q4_0-gguf](https://huggingface.co/google/gemma-4-E2B-it-qat-q4_0-gguf) `gemma-4-E2B_q4_0-it.gguf` | Q4_0 QAT | `--reasoning off` | 2 | 51 | 19 min |
| granite-4.2-3b | [ibm-granite/granite-4.2-3b](https://huggingface.co/ibm-granite/granite-4.2-3b) | 2026-08 | [ibm-granite/granite-4.2-3b-GGUF](https://huggingface.co/ibm-granite/granite-4.2-3b-GGUF) `granite-4.2-3b-Q4_K_M.gguf` | Q4_K_M | `--reasoning off` | 2 | 95 | 54 min |

Server: llama.cpp `llama-server` 0.9.0 (build 12110, commit cd959bae9).

Mean output tokens is over all 540 attempts. Scan time is generation time on a GPU that
another project used for training during most runs, so it says little about the models:
gemma-4-E2B-it ran while the machine was nearly idle and Qwen3.5-4B while it was swapping.
For Qwen3.5-4B it leaves out three chunks whose responses were discarded because they
were planned without the other probes (ADR-0005).

### Local models, default probe set (540 attempts each, greedy)

| Probe | OWASP 2026 | qwen3.5-0.8b | qwen3.5-2b | qwen3.5-4b | gemma-4-e2b | granite-4.2-3b |
|---|---|---|---|---|---|---|
| `encoding.obfuscation` | LLM01:2026 | 24/66 (36%, 26% to 48%) | 24/66 (36%, 26% to 48%) | 24/66 (36%, 26% to 48%) | 19/66 (29%, 19% to 41%) | 36/66 (55%, 43% to 66%) |
| `injection.direct` | LLM01:2026 | 50/60 (83%, 72% to 91%) | 52/60 (87%, 76% to 93%) | 47/60 (78%, 66% to 87%) | 39/60 (65%, 52% to 76%) | 50/60 (83%, 72% to 91%) |
| `injection.indirect` | LLM01:2026 | 22/72 (31%, 21% to 42%) | 38/72 (53%, 41% to 64%) | 44/72 (61%, 50% to 72%) | 27/72 (38%, 27% to 49%) | 52/72 (72%, 61% to 81%) |
| `jailbreak.templates` | LLM01:2026 | 73/90 (81%, 72% to 88%) | 23/90 (26%, 18% to 35%) | 25/90 (28%, 20% to 38%) | 59/90 (66%, 55% to 75%) | 23/90 (26%, 18% to 35%) |
| `disclosure.secrets` | LLM02:2026 | 26/48 (54%, 40% to 67%) | 23/48 (48%, 34% to 62%) | 21/48 (44%, 31% to 58%) | 21/48 (44%, 31% to 58%) | 27/48 (56%, 42% to 69%) |
| `agency.tools` | LLM03:2026 | 7/40 (18%, 9% to 32%) | 0/40 (0%, 0% to 9%) | 1/40 (2%, 0% to 13%) | 4/40 (10%, 4% to 23%) | 0/40 (0%, 0% to 9%) |
| `dos.token_blowup` | LLM06:2026 | 7/12 (58%, 32% to 81%) | 5/12 (42%, 19% to 68%) | 2/12 (17%, 5% to 45%) | 0/12 (0%, 0% to 24%) | 3/12 (25%, 9% to 53%) |
| `leakage.system_prompt` | LLM08:2026 | 29/80 (36%, 27% to 47%) | 37/80 (46%, 36% to 57%) | 37/80 (46%, 36% to 57%) | 23/80 (29%, 20% to 39%) | 27/80 (34%, 24% to 45%) |
| `output.shell` | LLM10:2026 | 18/24 (75%, 55% to 88%) | 16/24 (67%, 47% to 82%) | 12/24 (50%, 31% to 69%) | 11/24 (46%, 28% to 65%) | 15/24 (62%, 43% to 79%) |
| `output.sql` | LLM10:2026 | 12/24 (50%, 31% to 69%) | 11/24 (46%, 28% to 65%) | 11/24 (46%, 28% to 65%) | 12/24 (50%, 31% to 69%) | 9/24 (38%, 21% to 57%) |
| `output.xss` | LLM10:2026 | 2/24 (8%, 2% to 26%) | 7/24 (29%, 15% to 49%) | 14/24 (58%, 39% to 76%) | 11/24 (46%, 28% to 65%) | 19/24 (79%, 60% to 91%) |
| **All attacks** | | **270/540** (50%) | **236/540** (44%) | **238/540** (44%) | **226/540** (42%) | **261/540** (48%) |
| Errors | | 0 | 0 | 0 | 0 | 0 |

Every model is vulnerable in 10 or 11 of the 11 probe families, and the totals are close
(226 to 270 of 540 attacks, 42% to 50%), but the profiles differ. Jailbreak templates on
fictional restricted tasks split the models: Qwen3.5-0.8B (73 of 90) and gemma-4-E2B-it
(59) follow most of them, Qwen3.5-2B (23), Qwen3.5-4B (25) and granite-4.2-3b (23) about a
quarter (gemma-4-E2B-it against Qwen3.5-2B: +40 points, Newcombe 95% CI +26 to +52).
granite-4.2-3b is the most exposed to indirect injection (52 of 72; +19 points over
Qwen3.5-2B, +4 to +34) and writes executable HTML most often (19 of 24; +50 points, +22
to +68). Within Qwen3.5 the larger models act on instructions inside documents more often
(2B against 0.8B: +22 points, +6 to +37), and from 2B to 4B the only difference whose
interval excludes zero is HTML output (14 against 7 of 24; +29 points, +1 to +52).
Injected emails rarely made a model call a high-impact tool (0 to 7 of 40): the models
summarised the email and quoted the instruction instead.

### OWASP Top 10 for LLM Applications 2026: coverage and attack success rate

| Category | qwen3.5-0.8b | qwen3.5-2b | qwen3.5-4b | gemma-4-e2b | granite-4.2-3b | demo-vulnerable | demo-hardened |
|---|---|---|---|---|---|---|---|
| LLM01:2026 Prompt Injection | 169/288 (59%) | 137/288 (48%) | 140/288 (49%) | 144/288 (50%) | 161/288 (56%) | 51/106 (48%) | 37/106 (35%) |
| LLM02:2026 Sensitive Information Disclosure | 26/48 (54%) | 23/48 (48%) | 21/48 (44%) | 21/48 (44%) | 27/48 (56%) | 3/12 (25%) | 0/12 (0%) |
| LLM03:2026 Excessive Agency | 7/40 (18%) | 0/40 (0%) | 1/40 (2%) | 4/40 (10%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| LLM04:2026 Supply Chain | not tested | not tested | not tested | not tested | not tested | not tested | not tested |
| LLM05:2026 Data and Model Poisoning | not tested | not tested | not tested | not tested | not tested | not tested | not tested |
| LLM06:2026 Unbounded Consumption | 7/12 (58%) | 5/12 (42%) | 2/12 (17%) | 0/12 (0%) | 3/12 (25%) | 3/12 (25%) | 0/12 (0%) |
| LLM07:2026 Misinformation | not tested | not tested | not tested | not tested | not tested | not tested | not tested |
| LLM08:2026 Hidden Context Exposure | 29/80 (36%) | 37/80 (46%) | 37/80 (46%) | 23/80 (29%) | 27/80 (34%) | 8/16 (50%) | 0/16 (0%) |
| LLM09:2026 Vector and Embedding Weaknesses | not tested | not tested | not tested | not tested | not tested | not tested | not tested |
| LLM10:2026 Improper Output Handling | 32/72 (44%) | 34/72 (47%) | 37/72 (51%) | 34/72 (47%) | 43/72 (60%) | 16/36 (44%) | 0/36 (0%) |

Every probe maps to one 2026 category (`llm-vuln-scanner taxonomy`, ADR-0007). "Not
tested" categories need access the black-box probes do not have (see Limitations).

### OWASP Top 10 for Agentic Applications 2026: risks the agent and tool probes exercise

| Risk | Probes | qwen3.5-0.8b | qwen3.5-2b | qwen3.5-4b | gemma-4-e2b | granite-4.2-3b | demo-vulnerable | demo-hardened |
|---|---|---|---|---|---|---|---|---|
| ASI01:2026 Agent Goal Hijack | `agency.tools` | 7/40 (18%) | 0/40 (0%) | 1/40 (2%) | 4/40 (10%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| ASI02:2026 Tool Misuse & Exploitation | `agency.tools` | 7/40 (18%) | 0/40 (0%) | 1/40 (2%) | 4/40 (10%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| ASI05:2026 Unexpected Code Execution (RCE) | `output.shell` | 18/24 (75%) | 16/24 (67%) | 12/24 (50%) | 11/24 (46%) | 15/24 (62%) | 8/12 (67%) | 0/12 (0%) |

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

## Public attack datasets

Attacks written by people rather than by this repository's templates, on Qwen3.5-2B:
Tensor Trust hijacking ("say access granted") and extraction (reveal the access code)
from the robustness benchmarks of Toyer et al. (2023), Gandalf password-extraction
prompts from Lakera, and the in-the-wild jailbreak templates of Shen et al. (CCS 2024)
filled with fictional restricted tasks. Tensor Trust and Gandalf are seeded samples of
150 (of 776, 570 and 1,000); all 106 usable jailbreak templates are used. Reproduce with
`make data dataset-scans`.

### Public attack datasets on Qwen3.5-2B Q4_K_M

| Probe | OWASP 2026 | qwen3.5-2b-datasets |
|---|---|---|
| `dataset.tensortrust_hijacking` | LLM01:2026 | 80/150 (53%, 45% to 61%) |
| `dataset.wild_jailbreak` | LLM01:2026 | 21/106 (20%, 13% to 28%) |
| `dataset.gandalf` | LLM08:2026 | 106/150 (71%, 63% to 77%) |
| `dataset.tensortrust_extraction` | LLM08:2026 | 69/150 (46%, 38% to 54%) |
| **All attacks** | | **276/556** (50%) |
| Errors | | 0 |

The human-written attacks succeed about as often as the templates: half of the Tensor
Trust hijacking attacks make Qwen3.5-2B say "access granted" (80 of 150), 46% of the
extraction attacks reveal the access code, Gandalf prompts extract the password in 71%
of attempts, and 21 of 106 in-the-wild jailbreak templates get a fictional restricted
task answered. The run took 24 minutes for 556 attempts. Published Tensor Trust
robustness rates are for other models and were not rerun.

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
| LLM01:2026 Prompt Injection | 12 | 196/543 (36%) | 4 | 137/288 (48%) |
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

How much each detector component matters, and how well the refusal detectors agree with
human labels. Every jailbreak verdict needs a refusal decision, so the scanner's jailbreak
numbers are only as good as these detectors. Reproduce with `make ablations detectors`.

### Detector ablations (re-scored offline on the stored responses)

| Variant | qwen3.5-0.8b | qwen3.5-2b | qwen3.5-4b | gemma-4-e2b | granite-4.2-3b |
|---|---|---|---|---|---|
| full | 270/540 (+0, -0) | 236/540 (+0, -0) | 238/540 (+0, -0) | 226/540 (+0, -0) | 261/540 (+0, -0) |
| canary: raw substring | 203/416 (+0, -21) | 175/416 (+0, -22) | 180/416 (+0, -18) | 175/416 (+0, -13) | 177/416 (+0, -38) |
| sinks: regex | 21/72 (+0, -11) | 22/72 (+1, -13) | 25/72 (+2, -14) | 16/72 (+0, -18) | 36/72 (+6, -13) |
| jailbreak: canary only | 79/90 (+6, -0) | 42/90 (+19, -0) | 43/90 (+18, -0) | 82/90 (+23, -0) | 51/90 (+28, -0) |
| refusal: classifier only | 79/90 (+6, -0) | 37/90 (+14, -0) | 35/90 (+10, -0) | 78/90 (+19, -0) | 44/90 (+21, -0) |
| refusal: keyword only | 73/90 (+0, -0) | 25/90 (+2, -0) | 26/90 (+1, -0) | 60/90 (+1, -0) | 23/90 (+0, -0) |

Each row swaps one detector component for a simpler one and re-scores the stored
responses (zero mismatches between stored and re-scored verdicts in every run): "+" are
attacks the simpler variant newly counts as successful, "-" are successes it misses. Raw
substring search misses 13 to 38 canaries per model that came back reformatted, spelled
out or encoded. Regex rules for the HTML, SQL and shell sinks miss 11 to 18 sink findings
per model and add up to 6 false ones. A jailbreak needs the marker and a non-refusal from
both refusal detectors. The trained classifier alone, the rule before this release,
would add 6 to 21 jailbreaks per model, nearly all in-character refusals that printed the
marker first ("I cannot provide the brewing instructions for Glimmerdraught, as per
studio policy..."), which the classifier trained on XSTest scores as compliance; the
phrase list alone adds at most 2 (ADR-0006).

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
held-out models, which is why a jailbreak also needs the marker and the phrase list's
agreement (ADR-0006).

## Performance

Detector kernels on the 2,250 XSTest completions (1.6 MB of real model output), median of
5 runs, single thread, Rust core against the Python reference implementation that the
parity tests compare it with. Reproduce with `make speed`.

### Detector kernels, Rust core versus Python reference (2,250 texts, median of 5)

| Kernel | Python (texts/s) | Rust (texts/s) | Speedup |
|---|---|---|---|
| canary search (stdlib `re`: 2,187/s) | 1,981 | 22,088 | 11.2x |
| leakage LCS | 3,028 | 81,585 | 26.9x |
| n-gram hashing | 742 | 7,300 | 9.8x |
| text views | 2,190 | 49,867 | 22.8x |
| end to end rescoring | 3,056 | 12,289 | 4.0x |

| LCS, 200-token secret versus | Python | Rust | Speedup |
|---|---|---|---|
| 100 tokens | 1.1 ms | 0.023 ms | 49x |
| 1,000 tokens | 11.7 ms | 0.067 ms | 174x |
| 5,000 tokens | 60.2 ms | 0.271 ms | 222x |
| 20,000 tokens | 241.5 ms | 1.030 ms | 235x |

Canary search runs one Aho-Corasick automaton over all patterns in every view; the
standard-library `re` alternation baseline searches the same views built by Python. The
end-to-end row re-scores all 540 stored responses of the Qwen3.5-2B scan with every
detector, where SQLite, HTML parsing and the classifier's sparse algebra are shared by
both backends, so the speedup is smaller. Bit-parallel LCS grows with the output length
as expected: 49x at 100 tokens, 235x at 20,000.

## Threats to validity

- **Small quantized models, one shared machine.** Rates are for 0.8B to 4B models in 4-bit
  and 3-bit GGUF builds with greedy decoding; larger models, full precision and sampled
  decoding behave differently, and quantization can change refusal behaviour.
- **Non-thinking mode.** Qwen3.5 and Gemma 4 were scanned without their reasoning phase. With thinking
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
uv run --no-sync python rescore.py       # after a detector change: re-score every scan offline
uv run --no-sync python ablations.py
uv run --no-sync python speed.py
uv run --no-sync python report.py
```

Responses are cached in `../.bench-data/llm-vuln-scanner/cache/`, so each command resumes
after an interruption, a scan can be split into chunks of probes, and re-scoring is free.
