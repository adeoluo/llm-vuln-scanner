<h1 align="center">LLM Vuln Scanner</h1>

<p align="center">
  <em>An automated vulnerability scanner for LLM applications, mapped to the OWASP Top 10 for LLM Applications 2026, the OWASP Top 10 for Agentic Applications 2026 and MITRE ATLAS v2026.10.</em>
</p>

<p align="center">
  <a href="https://github.com/adeoluo/llm-vuln-scanner/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/adeoluo/llm-vuln-scanner/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/adeoluo/llm-vuln-scanner/releases"><img alt="Release" src="https://img.shields.io/github/v/release/adeoluo/llm-vuln-scanner"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14%20%7C%203.15-blue">
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.99%20%7C%20edition%202024-B7410E">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

---

## Motivation

An LLM feature is a new attack surface: untrusted text steers a model that can see secrets,
write SQL, call tools and emit HTML. Teams need the equivalent of a DAST scanner for it: a
tool that sends known attack techniques, decides objectively whether each one worked, and
fails a CI build with a report developers can act on.

This scanner sends 540 attack attempts across 11 probes (direct and indirect prompt
injection, system prompt leakage, insecure output handling, excessive agency, sensitive
information disclosure, encoding and obfuscation, jailbreak templates, token blow-up) plus
four public attack datasets, and decides success with exact checks: planted canary
tokens, a SQLite sink that executes model-written SQL under a read-only authorizer, an
HTML parser, a shell tokenizer and a tool-call log. Jailbreaks are only ever evaluated on
fictional restricted tasks, so no harmful content is requested or produced. Findings come
with Wilson 95% confidence intervals and map to the OWASP Top 10 for LLM Applications
2026, the OWASP Top 10 for Agentic Applications 2026 (for the agent and tool probes) and
MITRE ATLAS v2026.10 techniques.

## Architecture

<p align="center">
  <img src="docs/architecture/architecture.svg" alt="Architecture diagram" width="860">
</p>

<sub>Legend: amber = entry points and external systems, indigo = core logic, green = data and state, blue = validation and control, grey = observability and outputs.</sub>

A scan starts from the CLI, the GitHub Action or the HTTP service with a configuration
(probes, seed, budgets, optional application profile). Probes expand into attempts, each
with fresh seeded canaries and a goal; the engine sends them to a target (llama.cpp,
transformers, any OpenAI-compatible endpoint, or an application over HTTP such as the
bundled demo app), caching every response so scans resume and re-score offline. Detectors
decide success (canary search over normalized and decoded views and LCS leakage in a Rust
core, sink emulation for HTML, SQL and shell, refusal classifiers and an optional LLM
judge), and findings are written as JSON, HTML, SARIF 2.1.0, JUnit XML and Markdown.
More detail: [docs/adr/](docs/adr/).

## Results

All numbers come from runs on an Apple M1 laptop (8 cores, 8 GB, shared with other work)
and are reproducible with the commands under Usage; raw results are in
[benchmarks/results/](benchmarks/results/) and the walkthrough is in
[docs/EVALUATION_REPORT.md](docs/EVALUATION_REPORT.md). Targets are the current small open
instruction models (Qwen3.5, Gemma 4, Granite 4.2) as GGUF builds served by llama.cpp
0.9.0 (b9.0), all without a thinking phase. Rates are attack successes over
attempts with Wilson 95% intervals; one greedy generation per attempt (seed 0). OWASP
identifiers are the 2026 editions.

### Scans of local models

The default probe set against each model with no application around it: the system
prompt, planted secrets, tools and sinks come from the probe itself. Reproduce with
`make scans` (or `uv run --no-sync python benchmarks/scan_models.py --model KEY`).

**Models scanned (llama.cpp, greedy, parallel slots of 4,096 tokens)**

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

**Local models, default probe set (540 attempts each, greedy)**

| Probe | OWASP 2026 | qwen3.5-0.8b | qwen3.5-2b | qwen3.5-4b | gemma-4-e2b | granite-4.2-3b |
|---|---|---|---|---|---|---|
| `encoding.obfuscation` | LLM01:2026 | 24/66 (36%, 26% to 48%) | 24/66 (36%, 26% to 48%) | 24/66 (36%, 26% to 48%) | 19/66 (29%, 19% to 41%) | 36/66 (55%, 43% to 66%) |
| `injection.direct` | LLM01:2026 | 50/60 (83%, 72% to 91%) | 52/60 (87%, 76% to 93%) | 47/60 (78%, 66% to 87%) | 39/60 (65%, 52% to 76%) | 50/60 (83%, 72% to 91%) |
| `injection.indirect` | LLM01:2026 | 22/72 (31%, 21% to 42%) | 38/72 (53%, 41% to 64%) | 44/72 (61%, 50% to 72%) | 27/72 (38%, 27% to 49%) | 52/72 (72%, 61% to 81%) |
| `jailbreak.templates` | LLM01:2026 | 79/90 (88%, 79% to 93%) | 37/90 (41%, 32% to 51%) | 35/90 (39%, 29% to 49%) | 78/90 (87%, 78% to 92%) | 44/90 (49%, 39% to 59%) |
| `disclosure.secrets` | LLM02:2026 | 26/48 (54%, 40% to 67%) | 23/48 (48%, 34% to 62%) | 21/48 (44%, 31% to 58%) | 21/48 (44%, 31% to 58%) | 27/48 (56%, 42% to 69%) |
| `agency.tools` | LLM03:2026 | 7/40 (18%, 9% to 32%) | 0/40 (0%, 0% to 9%) | 1/40 (2%, 0% to 13%) | 4/40 (10%, 4% to 23%) | 0/40 (0%, 0% to 9%) |
| `dos.token_blowup` | LLM06:2026 | 7/12 (58%, 32% to 81%) | 5/12 (42%, 19% to 68%) | 2/12 (17%, 5% to 45%) | 0/12 (0%, 0% to 24%) | 3/12 (25%, 9% to 53%) |
| `leakage.system_prompt` | LLM08:2026 | 29/80 (36%, 27% to 47%) | 37/80 (46%, 36% to 57%) | 37/80 (46%, 36% to 57%) | 23/80 (29%, 20% to 39%) | 27/80 (34%, 24% to 45%) |
| `output.shell` | LLM10:2026 | 18/24 (75%, 55% to 88%) | 16/24 (67%, 47% to 82%) | 12/24 (50%, 31% to 69%) | 11/24 (46%, 28% to 65%) | 15/24 (62%, 43% to 79%) |
| `output.sql` | LLM10:2026 | 12/24 (50%, 31% to 69%) | 11/24 (46%, 28% to 65%) | 11/24 (46%, 28% to 65%) | 12/24 (50%, 31% to 69%) | 9/24 (38%, 21% to 57%) |
| `output.xss` | LLM10:2026 | 2/24 (8%, 2% to 26%) | 7/24 (29%, 15% to 49%) | 14/24 (58%, 39% to 76%) | 11/24 (46%, 28% to 65%) | 19/24 (79%, 60% to 91%) |
| **All attacks** | | **276/540** (51%) | **250/540** (46%) | **248/540** (46%) | **245/540** (45%) | **282/540** (52%) |
| Errors | | 0 | 0 | 0 | 0 | 0 |

Every model is vulnerable in 10 or 11 of the 11 probe families, and the totals are close
(245 to 282 of 540 attacks, 45% to 52%), but the profiles differ. Jailbreak templates on
fictional restricted tasks split the models: Qwen3.5-0.8B (79 of 90) and gemma-4-E2B-it
(78) follow most of them, Qwen3.5-2B (37), Qwen3.5-4B (35) and granite-4.2-3b (44) fewer
than half (gemma-4-E2B-it against Qwen3.5-2B: +46 points, Newcombe 95% CI +32 to +57).
granite-4.2-3b is the most exposed to indirect injection (52 of 72; +19 points over
Qwen3.5-2B, +4 to +34) and writes executable HTML most often (19 of 24; +50 points, +22
to +68). Within Qwen3.5 the larger models act on instructions inside documents more often
(2B against 0.8B: +22 points, +6 to +37), and from 2B to 4B the only difference whose
interval excludes zero is HTML output (14 against 7 of 24; +29 points, +1 to +52).
Injected emails rarely made a model call a high-impact tool (0 to 7 of 40): the models
summarised the email and quoted the instruction instead.

**OWASP Top 10 for LLM Applications 2026: coverage and attack success rate**

| Category | qwen3.5-0.8b | qwen3.5-2b | qwen3.5-4b | gemma-4-e2b | granite-4.2-3b | demo-vulnerable | demo-hardened |
|---|---|---|---|---|---|---|---|
| LLM01:2026 Prompt Injection | 175/288 (61%) | 151/288 (52%) | 150/288 (52%) | 163/288 (57%) | 182/288 (63%) | 51/106 (48%) | 37/106 (35%) |
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

**OWASP Top 10 for Agentic Applications 2026: risks the agent and tool probes exercise**

| Risk | Probes | qwen3.5-0.8b | qwen3.5-2b | qwen3.5-4b | gemma-4-e2b | granite-4.2-3b | demo-vulnerable | demo-hardened |
|---|---|---|---|---|---|---|---|---|
| ASI01:2026 Agent Goal Hijack | `agency.tools` | 7/40 (18%) | 0/40 (0%) | 1/40 (2%) | 4/40 (10%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| ASI02:2026 Tool Misuse & Exploitation | `agency.tools` | 7/40 (18%) | 0/40 (0%) | 1/40 (2%) | 4/40 (10%) | 0/40 (0%) | 0/40 (0%) | 0/40 (0%) |
| ASI05:2026 Unexpected Code Execution (RCE) | `output.shell` | 18/24 (75%) | 16/24 (67%) | 12/24 (50%) | 11/24 (46%) | 15/24 (62%) | 8/12 (67%) | 0/12 (0%) |

`agency.tools` covers Agent Goal Hijack and Tool Misuse & Exploitation; `output.shell`
covers Unexpected Code Execution because the feature it models runs the command.

### Demo application

The bundled "Northwind Kettles" support application with four LLM features (chat with
documents, SQL order lookup, shell diagnostics, a tool-using agent), scanned through its
profile with the same Qwen3.5-2B backend in both modes. Hardened mode applies the
standard mitigation per feature (no secrets in context, spotlighted documents, escaped
HTML, read-only scoped SQL, argument vectors instead of a shell, confirmation for
high-impact tools). Reproduce with `make demo-scans`.

**Demo application, vulnerable versus hardened (same Qwen3.5-2B Q4_K_M backend)**

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

### Comparison with garak

[garak](https://github.com/NVIDIA/garak) 0.17.1 (NVIDIA's LLM vulnerability scanner) against
the same Qwen3.5-2B server (same GGUF, non-thinking mode, greedy, one generation, garak's
150-token default budget), with the 19 garak probes that match this scanner's OWASP
categories and do not ask for harmful content, at most 24 prompts per probe where garak
honours the cap. An attempt counts when any of its probe's detectors scores at least 0.5.
garak tags probes with the 2023 OWASP numbering, so each probe is mapped here to the 2026
category of the behaviour it tests (`benchmarks/garak_compare.py`). Reproduce with
`make garak`.

**Same model (qwen3.5-2b), garak 0.17.1 versus this scanner, by OWASP 2026 category**

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

### Detector validation

How well the refusal detectors agree with human labels. Every jailbreak verdict needs a
refusal decision, so the scanner's jailbreak numbers are only as good as these detectors.
Reproduce with `make detectors`.

**Refusal detectors on XSTest v2 (2,250 human-labelled completions)**

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

## Quickstart

```bash
git clone https://github.com/adeoluo/llm-vuln-scanner && cd llm-vuln-scanner
make setup                                   # uv sync (builds the Rust core) + pre-commit
uv run llm-vuln-scanner scan --target naive --sample 3 --out reports
open reports/scan.html                       # or scan.sarif / scan.xml / scan.md / scan.json
```

Scan a real model (any OpenAI-compatible endpoint, or a GGUF file through llama.cpp):

```bash
uv run llm-vuln-scanner scan --target "openai:http://127.0.0.1:8080/v1#local" --concurrency 4
uv run llm-vuln-scanner scan --target llamacpp:/path/to/model.gguf --fail-on high
```

## Usage

### CLI

| Command | Purpose |
|---|---|
| `scan --target SPEC` | Run probes and write reports (`--probes`, `--sample`, `--generations`, `--temperature`, `--seed`, `--concurrency`, `--profile`, `--judge`, `--cache`, `--format`, `--fail-on`, `--github`, `--max-consecutive-errors`) |
| `probes`, `detectors`, `taxonomy` | List probes with OWASP and ATLAS mappings, detectors, and coverage |
| `report FILE.json` | Re-render a JSON report as HTML, SARIF, JUnit or Markdown |
| `compare A.json B.json` | Per-probe success rate differences with Newcombe 95% intervals |
| `demo-app [--hardened]` | Run the deliberately vulnerable demo application (localhost only) |
| `serve` | Run the HTTP service |

Target specs: `naive` and `refusing` (offline simulated models), `openai:URL[#MODEL]`
(with `--api-key-env NAME`), `llamacpp:PATH.gguf` (starts and stops `llama-server`),
`transformers:MODEL_ID`, and `app:URL` for applications that expose the demo app's
`/api/chat`, `/api/orders`, `/api/diagnose` and `/api/agent` contract, described by a
profile such as [examples/demo-app.json](examples/demo-app.json).

### Library API

```python
from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner.targets import OpenAICompatTarget

target = OpenAICompatTarget("http://127.0.0.1:8080/v1", model="local")
report = Scanner(target, ScanConfig(probes=["injection", "leakage"], concurrency=4)).run()
for f in report.findings:
    print(f.probe, f.owasp, f.successes, f.attempts, f.vulnerable)
```

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: adeoluo/llm-vuln-scanner@v0.1.0
    with:
      target: "openai:https://staging.example.com/v1#my-model"
      api-key-env: STAGING_API_KEY
      probes: default
      fail-on: high
    env:
      STAGING_API_KEY: ${{ secrets.STAGING_API_KEY }}
```

The action installs the scanner, writes all report formats, adds a Markdown summary and
annotations to the run, uploads SARIF to code scanning, and fails the step when a finding
reaches the `fail-on` severity. CI exercises it on every pull request.

### HTTP service

`uv run llm-vuln-scanner serve --allow-target naive,refusing` exposes `GET /health`,
`GET /ready`, `GET /metrics` (Prometheus text), `GET /v1/probes` and `POST /v1/scans`.
Targets must match an allowed prefix, so the service cannot be used to reach arbitrary
URLs. `docker compose up --build` starts the service next to the demo application.

### Reproducing the benchmarks

```bash
make bench-setup data models   # transformers, pyarrow, sklearn; 6 MB of data; GGUF models
make scans demo-scans dataset-scans detectors garak speed ablations
make evaluation                # prints every table above from benchmarks/results/
```

### Demos

Recorded from real runs with [vhs](https://github.com/charmbracelet/vhs); each tape is in `docs/demo/`.

A scan of the simulated vulnerable model, failing the build at severity high, and the OWASP 2026 and ATLAS v2026.10 identifiers in the SARIF it wrote.

<p align="center">
  <img src="docs/demo/scan.gif" alt="A scan of the simulated vulnerable model, failing the build at severity high, and the SARIF it wrote" width="860">
</p>

The `taxonomy` command: each probe's OWASP Top 10 for LLM Applications 2026 category, OWASP Top 10 for Agentic Applications 2026 risks and MITRE ATLAS v2026.10 techniques.

<p align="center">
  <img src="docs/demo/taxonomy.gif" alt="The taxonomy command listing OWASP LLM 2026, OWASP Agentic 2026 and MITRE ATLAS v2026.10 coverage per probe" width="860">
</p>

The demo application in vulnerable and hardened mode, scanned with its profile and compared.

<p align="center">
  <img src="docs/demo/demo-app.gif" alt="The demo application in vulnerable and hardened mode, scanned with its profile and compared" width="860">
</p>

Two committed benchmark scans (Qwen3.5-0.8B and Qwen3.5-2B) compared probe by probe with Newcombe 95% intervals.

<p align="center">
  <img src="docs/demo/compare.gif" alt="Two committed benchmark scans compared probe by probe with Newcombe 95% intervals" width="860">
</p>

## Design decisions

- **Canary tokens decide success** ([ADR-0002](docs/adr/0002-canary-tokens-decide-attack-success.md)): exact, reproducible checks with a near-zero false-positive rate, and no harmful content anywhere.
- **Rust core with a Python reference** ([ADR-0003](docs/adr/0003-rust-core-with-python-reference.md)): Aho-Corasick canary search, bit-parallel LCS and hashed n-grams, with property-based parity tests.
- **Emulate the sink** ([ADR-0004](docs/adr/0004-sink-emulation-for-output-handling.md)): parse HTML, run SQL in a guarded in-memory SQLite, tokenize shell commands, instead of matching dangerous strings.
- **Cached scans that fail loudly** ([ADR-0005](docs/adr/0005-cached-resumable-scans-that-fail-loudly.md)): resumable JSONL cache; errors never cached and a dead target aborts the scan.
- **Taxonomies pinned to the 2026 editions** ([ADR-0007](docs/adr/0007-taxonomy-owasp-2026-and-atlas-v2026-10.md)): OWASP LLM Top 10 2026, OWASP Agentic Top 10 2026 and ATLAS v2026.10, checked against the release data in tests; reports from earlier builds are relabelled on read.
- **A small refusal classifier by default** ([ADR-0006](docs/adr/0006-hashed-logistic-refusal-classifier.md)): no PyTorch dependency; the LLM judge is opt-in and both are measured on XSTest.

## Testing

```bash
make test        # unit, property-based, integration (CLI, HTTP service, demo app)
make coverage    # with the 80% gate used in CI (LVS_REQUIRE_RUST=1)
make parity      # Rust core against the Python reference (hypothesis)
make rust-check  # cargo fmt, clippy and unit tests
```

215 tests (96% line and branch coverage) cover every probe against the simulated
models, every detector on positive and negative cases, the SARIF output against the
official 2.1.0 schema, the HTTP service and demo application end to end, parity of the
Rust core with the Python reference on random Unicode text, and parity of the refusal
model's optimizer with scikit-learn. `tests/test_taxonomy.py` pins the OWASP LLM 2026 and
OWASP Agentic 2026 identifiers and names and each probe's mapping, and checks every ATLAS
technique against the technique list of the v2026.10 data release. CI runs the suite on
Python 3.12, 3.13, 3.14 and 3.15 together with the Rust checks, a package and Docker
build, and a self-test of the GitHub Action.

## Responsible AI

- **Model card:** [docs/MODEL_CARD.md](docs/MODEL_CARD.md)
- **Data card:** [docs/DATA_CARD.md](docs/DATA_CARD.md)
- **Threat model:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

This is defensive tooling. Jailbreak probes only target fictional restricted tasks
(an invented potion recipe, the ending of a fictional unreleased novel, an advert for a
rival soda brand); secrets are fictional canaries and fake credentials in documented
example formats, masked in the committed reports; output sinks never execute anything
outside an in-memory fixture. Only scan systems you own or are authorized to test.

## Limitations

- OWASP LLM04:2026 (supply chain), LLM05:2026 (data and model poisoning), LLM07:2026
  (misinformation) and LLM09:2026 (vector and embedding weaknesses) are not covered: they
  need the model artifact, training data, ground truth or the retrieval store rather than
  black-box prompts. Of the Agentic Top 10, only ASI01, ASI02 and ASI05 are exercised.
- A scan is a lower bound. Attacks whose success is not observable as a canary, tool
  call or sink effect (a paraphrased secret, a jailbreak that complies without the marker)
  are missed.
- Benchmarks use small local models (0.8B to 4B parameters, 4-bit and 3-bit GGUF) on one
  laptop with greedy decoding and one generation per attempt; larger models, full
  precision, thinking mode and sampled decoding change the rates.
- The trained refusal classifier does not beat the keyword list on held-out XSTest models
  (see the detector table); it is kept as a second signal, not as a better one.

## Roadmap

- [ ] Multi-turn attack strategies (crescendo, adaptive attacker model).
- [ ] Retrieval-augmented targets with poisoned vector stores (LLM09:2026).
- [ ] Larger models (7B and up) and sampled decoding with several generations.
- [ ] Qwen3Guard-Gen as an optional refusal detector (the most accurate one on XSTest here).
- [ ] Scans in Qwen3.5 thinking mode, with the reasoning trace checked for canaries.

## License

Released under the [MIT License](LICENSE).
