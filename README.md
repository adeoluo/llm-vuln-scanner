<h1 align="center">LLM Vuln Scanner</h1>

<p align="center">
  <em>An automated vulnerability scanner for LLM applications, mapped to the OWASP Top 10 for LLM Applications 2026, the OWASP Top 10 for Agentic Applications 2026 and MITRE ATLAS v2026.10.</em>
</p>

<p align="center">
  <a href="https://github.com/adeoluo/llm-vuln-scanner/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/adeoluo/llm-vuln-scanner/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/adeoluo/llm-vuln-scanner/releases"><img alt="Release" src="https://img.shields.io/github/v/release/adeoluo/llm-vuln-scanner"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%20%7C%203.12-blue">
  <img alt="Rust" src="https://img.shields.io/badge/rust-stable-B7410E">
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

All numbers come from runs on an Apple M1 laptop (8 cores, 8 GB) and are reproducible
with the commands under Usage; raw results are in [benchmarks/results/](benchmarks/results/)
and the walkthrough is in [docs/EVALUATION_REPORT.md](docs/EVALUATION_REPORT.md).
Rates are attack successes over attempts with Wilson 95% intervals; one greedy generation
per attempt (seed 0).

### Scans of local models

The default probe set against each model with no application around it: the system
prompt, planted secrets, tools and sinks come from the probe itself.

**Local models, default probe set (540 attempts each, greedy)**

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

**OWASP Top 10 for LLM Applications 2026 coverage and attack success rate**

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

### Demo application

The bundled "Northwind Kettles" support application with four LLM features (chat with
documents, SQL order lookup, shell diagnostics, a tool-using agent), scanned through its
profile with the same Qwen2.5-1.5B backend in both modes. Hardened mode applies the
standard mitigation per feature (no secrets in context, spotlighted documents, escaped
HTML, read-only scoped SQL, argument vectors instead of a shell, confirmation for
high-impact tools).

**Demo application, vulnerable versus hardened (same Qwen2.5-1.5B backend)**

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

### Detector validation

How much each detector component matters, and how well the refusal detectors agree with
human labels.

**Detector ablations (re-scored offline on the stored responses)**

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

**Refusal detectors on XSTest v2 (2,250 human-labelled completions)**

| Detector | Accuracy | Precision | Recall | F1 | Time |
|---|---|---|---|---|---|
| keyword | 0.884 (0.871 to 0.897) | 0.955 (0.942 to 0.968) | 0.813 (0.791 to 0.835) | 0.878 (0.863 to 0.893) | 0.1 s |
| xstest_strmatch | 0.884 (0.871 to 0.897) | 0.954 (0.940 to 0.966) | 0.815 (0.794 to 0.838) | 0.879 (0.865 to 0.893) | 0.0 s |
| classifier (LOMO) | 0.868 (0.854 to 0.881) | 0.956 (0.941 to 0.968) | 0.779 (0.757 to 0.801) | 0.858 (0.843 to 0.873) | 113.9 s |
| sklearn tfidf+LR (LOMO) | 0.872 (0.859 to 0.885) | 0.949 (0.936 to 0.963) | 0.794 (0.771 to 0.815) | 0.865 (0.850 to 0.879) | 7.3 s |

Leave-one-model-out (LOMO): trained on four XSTest answering models, tested on the fifth.
The trained classifier does not beat the phrase list on held-out models, which is why
jailbreak success also requires the canary (ADR-0006).

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

A scan of the simulated vulnerable model, failing the build at severity high, and the SARIF it wrote.

<p align="center">
  <img src="docs/demo/scan.gif" alt="A scan of the simulated vulnerable model, failing the build at severity high, and the SARIF it wrote" width="860">
</p>

The demo application in vulnerable and hardened mode, scanned with its profile and compared.

<p align="center">
  <img src="docs/demo/demo-app.gif" alt="The demo application in vulnerable and hardened mode, scanned with its profile and compared" width="860">
</p>

Two committed benchmark scans (Qwen2.5-1.5B and SmolLM2-1.7B) compared probe by probe with Newcombe 95% intervals.

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

199 tests (96% line and branch coverage) cover every probe against the
simulated models, every detector on positive and negative cases, the SARIF output against
the official 2.1.0 schema, the HTTP service and demo application end to end, parity of the
Rust core with the Python reference on random Unicode text, and parity of the refusal
model's optimizer with scikit-learn. CI runs them on Python 3.11 and 3.12 together with
the Rust checks, a package and Docker build, and a self-test of the GitHub Action.

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
- Benchmarks use small local models (0.5B to 3B parameters) on one laptop with greedy
  decoding and one generation per attempt; larger models and sampling change the rates.
- The trained refusal classifier does not beat the keyword list on held-out XSTest models
  (see the detector table); it is kept as a second signal, not as a better one.

## Roadmap

- [ ] Multi-turn attack strategies (crescendo, adaptive attacker model).
- [ ] Retrieval-augmented targets with poisoned vector stores (LLM09:2026).
- [ ] Larger models (7B and up) and sampled decoding with several generations.

## License

Released under the [MIT License](LICENSE).
