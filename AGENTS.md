# AGENTS.md

Working notes for coding agents and contributors in **LLM Vuln Scanner**. The [README](README.md)
explains what the project does and why; this file explains how to change it safely.

## Project

An automated vulnerability scanner for LLM applications, mapped to the OWASP Top 10 for LLM Applications 2026, the OWASP Top 10 for Agentic Applications 2026 and MITRE ATLAS v2026.10.

## Layout

- `action.yml`: action metadata: inputs, outputs, runtime
- `benchmarks/`: benchmark scripts and recorded results
- `docker-compose.yml`: local container setup
- `docs/`: documentation, architecture diagram source and render, design records
- `examples/`: runnable examples and sample configuration
- `rust/`: Rust core compiled into a Python extension with PyO3
- `scripts/`: maintenance scripts (release, assets, data)
- `src/`: library and service source
- `tests/`: test suite

Key modules:

- `rust/src/aho.rs`: Aho-Corasick automaton over bytes (Aho and Corasick, 1975).
- `rust/src/canary.rs`: Canary search across all views; mirrors `llm_vuln_scanner.matching.find_canaries_py`.
- `rust/src/lcs.rs`: Bit-parallel longest common subsequence length.
- `rust/src/lib.rs`: Rust core of llm-vuln-scanner.
- `rust/src/ngrams.rs`: Hashed n-gram counts for the refusal classifier; mirrors `llm_vuln_scanner.detectors.refusal.ngram_counts_py` (input already normalized).
- `rust/src/python.rs`: PyO3 bindings, built by maturin into the `llm_vuln_scanner.lvs_rs` module.
- `rust/src/views.rs`: Text views searched by the canary detector; mirrors `llm_vuln_scanner.textviews`.
- `src/llm_vuln_scanner/__init__.py`: LLM Vuln Scanner: probes, detectors and reports for LLM application security testing.
- `src/llm_vuln_scanner/canary.py`: Canary tokens: unique strings planted in prompts so that success is checked exactly.
- `src/llm_vuln_scanner/cli.py`: Command-line interface: ``python -m llm_vuln_scanner <command>``.
- `src/llm_vuln_scanner/demo_app/__init__.py`: The deliberately vulnerable demo application; see :mod:`llm_vuln_scanner.demo_app.app`.
- `src/llm_vuln_scanner/demo_app/app.py`: A deliberately vulnerable LLM application for exercising the scanner.
- `src/llm_vuln_scanner/detectors/__init__.py`: Detectors package; see :mod:`llm_vuln_scanner.detectors.base`.
- `src/llm_vuln_scanner/detectors/agency.py`: Excessive agency: tool calls the model should not have made.
- `src/llm_vuln_scanner/detectors/base.py`: Detectors decide, for one attempt and one response, whether the attack succeeded.
- `src/llm_vuln_scanner/detectors/canary.py`: Canary detectors: planted tokens, system-prompt similarity and success regexes.
- `src/llm_vuln_scanner/detectors/dos.py`: Model denial of service: output that runs to the token limit on request.
- `src/llm_vuln_scanner/detectors/judge.py`: LLM judge: a local model grades whether a restricted request was answered.
- `src/llm_vuln_scanner/detectors/refusal.py`: Refusal detection: did the model decline a restricted request? Jailbreak probes ask for something the system prompt forbids (always a fictional task) and check two things: whether the compliance...
- `src/llm_vuln_scanner/detectors/secrets.py`: Secret formats: credentials and personal data shapes in model output.
- `src/llm_vuln_scanner/detectors/sinks.py`: Sink detectors: would a downstream component execute what the model wrote? Improper output handling (OWASP LLM10:2026) is a property of the application: the model's text reaches an HTML page, a SQL...
- `src/llm_vuln_scanner/engine.py`: The scan engine: expands probes, queries the target, runs detectors, aggregates.
- `src/llm_vuln_scanner/matching.py`: Canary search and system-prompt similarity, with a Rust core and a Python reference.
- `src/llm_vuln_scanner/probes/__init__.py`: Probes package; see :mod:`llm_vuln_scanner.probes.base`.
- `src/llm_vuln_scanner/probes/agency.py`: Excessive agency probes (OWASP LLM03:2026; Agentic ASI01, ASI02; ATLAS AML.T0053, AML.T0086).
- `src/llm_vuln_scanner/probes/base.py`: Probe interface, registry and the scan context probes build attempts from.
- `src/llm_vuln_scanner/probes/datasets.py`: Probes built from published attack datasets (opt-in, need ``--data-dir``).
- `src/llm_vuln_scanner/probes/disclosure.py`: Sensitive information disclosure probes (OWASP LLM02:2026; ATLAS AML.T0085.002, AML.T0055).
- `src/llm_vuln_scanner/probes/dos.py`: Model denial of service probes (OWASP LLM06:2026; ATLAS AML.T0029, AML.T0034.001).
- `src/llm_vuln_scanner/probes/encoding.py`: Encoding and obfuscation probes (OWASP LLM01:2026; ATLAS AML.T0068).
- `src/llm_vuln_scanner/probes/injection.py`: Prompt injection probes (OWASP LLM01:2026; ATLAS AML.T0051).
- `src/llm_vuln_scanner/probes/jailbreak.py`: Jailbreak probes on fictional restricted tasks (OWASP LLM01:2026; ATLAS AML.T0054).
- `src/llm_vuln_scanner/probes/leakage.py`: System prompt leakage probes (OWASP LLM08:2026 Hidden Context Exposure; ATLAS AML.T0085.003).
- `src/llm_vuln_scanner/probes/output.py`: Improper output handling probes (OWASP LLM10:2026; ATLAS AML.T0077, AML.T0050).
- `src/llm_vuln_scanner/probes/scenarios.py`: Fictional applications that model-mode probes wrap their attacks in.
- `src/llm_vuln_scanner/report/__init__.py`: Report renderers.
- `src/llm_vuln_scanner/report/html.py`: Self-contained HTML report (no external assets, every value HTML-escaped).
- `src/llm_vuln_scanner/report/junit.py`: JUnit XML output: one test suite per probe, one test case per attempt.
- `src/llm_vuln_scanner/report/markdown.py`: Markdown summary (GitHub step summaries, pull request comments) and workflow annotations (``::error``/``::warning`` lines GitHub Actions turns into alerts).
- `src/llm_vuln_scanner/report/sarif.py`: SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

## Commands

| Command | Purpose |
|---|---|
| `make help` | Show this help |
| `make setup` | Install dependencies (compiles the Rust core) and pre-commit hooks |
| `make bench-setup` | Everything the full-scale benchmarks need (transformers, scikit-learn, pyarrow) |
| `make format` | Format automatically |
| `make lint` | Lint (no fixes) |
| `make type` | Type-check |
| `make test` | Run tests |
| `make coverage` | Tests with the coverage gate used in CI |
| `make rust-check` | Rust core: fmt, clippy (with and without Python), unit tests |
| `make rust-develop` | Rebuild the Rust core into .venv after editing rust/ |
| `make parity` | Rust versus Python parity tests |
| `make data` | Download the public datasets (about 6 MB, outside the repository) |
| `make models` | Download the local models into the Hugging Face cache (about 11 GB; MODELS="qwen3.5-2b ..." for a subset) |
| `make atlas-snapshot` | Rewrite tests/data/atlas-2026.10-techniques.json from the ATLAS v2026.10 release asset |
| `make train-refusal` | Retrain the bundled refusal classifier on XSTest v2 |
| `make scans` | Full scans of the local models (writes benchmarks/results/scans/) |
| `make demo-scans` | Scan the demo application (vulnerable and hardened) backed by Qwen3.5-2B |
| `make dataset-scans` | Tensor Trust, Gandalf and in-the-wild jailbreak probes on Qwen3.5-2B (seeded samples of 300) |
| `make detectors` | Refusal detectors against XSTest human labels (keyword, classifier, reference models, judge) |
| `make garak` | garak on the same model (separate venv; see benchmarks/garak/README.md) |
| `make speed` | Detector throughput, Rust versus Python |
| `make ablations` | Detector ablations re-scored on the stored scan responses |
| `make evaluation` | Print the README tables from benchmarks/results/ |
| `make run` | Run the scanner HTTP service |
| `make demo-app` | Run the deliberately vulnerable demo application (offline backend) |
| `make diagram` | Render the architecture diagram to SVG |
| `make docker-build` | Build the image |
| `make docker-up` | Scanner service and demo application via docker compose |
| `make demo` | Record the demo GIFs with vhs |
| `make clean` | Remove caches and artifacts |
| `make all` | Full local gate (mirror of continuous integration) |
| `make changelog` | Regenerate CHANGELOG.md from Conventional Commits (git-cliff) |
| `make cut-release` | Cut a release locally: version bump, changelog, tag, GitHub release (RELEASE_VERSION=vX.Y.Z optional) |

Run the full local gate (`make all`) before committing; CI runs the same checks.

## Conventions

- Commits follow Conventional Commits (`feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`).
  The changelog and the next version number are derived from them.
- Every number quoted in the README is produced by a command in this repository. When behavior
  changes, rerun that command and update the number in the same commit.
- When a component is added, removed or renamed, update `docs/architecture/architecture.mmd`
  and re-render `architecture.svg` so the diagram matches the code.
- README sections keep their fixed order. Prose avoids em and en dashes and promotional wording.
- Tests accompany behavior changes; a bug fix comes with a test that fails without it.
- Releases are cut with `make cut-release`.

## Python notes

- Python is managed with `uv`; run commands through `uv run` so the locked environment is used.
- Lint and format with `ruff`; type-check with `mypy`; tests use `pytest`.
- Public functions carry type hints and a docstring that states the contract, not the steps.

## Rust notes

- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` must pass.
- No `unwrap()` in library code paths that can fail at runtime; return a typed error.
- Unsafe code is limited to the places that need a syscall and carries a `SAFETY:` comment.
