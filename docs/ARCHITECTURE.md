# Architecture

The diagram in the README shows the layers; this page maps them to modules and follows
one attempt through the system.

## Modules

| Layer | Module | Responsibility |
|---|---|---|
| Interfaces | `cli.py` | `scan`, `probes`, `detectors`, `taxonomy`, `report`, `compare`, `demo-app`, `serve` |
| | `action.yml` | GitHub Action: install, scan with annotations and a step summary, SARIF upload, severity gate |
| | `service.py` | HTTP service (`/health`, `/ready`, `/metrics`, `/v1/probes`, `/v1/scans`) with a target allow list |
| Configuration | `engine.ScanConfig`, `probes/base.load_profile` | probes, seed, generations, budgets, error guard; application profiles |
| Probes | `probes/*.py` | 11 probe families plus 4 dataset probes; each expands into `Attempt`s with a `Goal` |
| | `canary.py` | seeded canary tokens (`LVS-7F3A-PELICAN`) |
| | `taxonomy.py` | OWASP LLM Top 10 (2025) and MITRE ATLAS identifiers per probe |
| Engine | `engine.py` | plan, thread pool, response cache, error guard, evaluation, findings with Wilson intervals |
| Targets | `targets/*.py` | simulated models, OpenAI-compatible HTTP, llama.cpp launcher, transformers, application targets |
| | `demo_app/app.py` | the deliberately vulnerable application and its hardened mode |
| Detection | `detectors/canary.py`, `matching.py`, `textviews.py` | canary search over text views, LCS leakage, regex goals |
| | `detectors/sinks.py` | HTML, SQLite, shell and markdown exfiltration sinks |
| | `detectors/secrets.py`, `agency.py`, `dos.py` | planted secret formats (with Luhn), forbidden tool calls, token budget exhaustion |
| | `detectors/refusal.py`, `judge.py` | keyword and trained refusal detectors, LLM judge |
| | `rust/src/*.rs` (`lvs_rs`) | Aho-Corasick canary search, text views, bit-parallel LCS, hashed n-grams |
| Reports | `report/*.py`, `stats.py` | JSON, HTML, SARIF 2.1.0, JUnit XML, Markdown; Wilson and Newcombe intervals |

## One attempt, end to end

1. `Scanner.plan()` asks every selected probe for its attempts. A probe builds the
   messages (system prompt, untrusted document, user turn), plants canaries from the
   seeded `CanaryFactory`, and states the goal: canaries that must not appear, the
   confidential system prompt, the sink the output feeds, forbidden tools, whether a
   refusal is expected.
2. The engine computes the cache key (target, a digest of everything the target sees,
   seed, temperature, token budget). A cached response is reused; otherwise the target is
   called and a successful response is appended to the JSONL cache.
3. Each of the attempt's detectors returns a `Detection(hit, score, evidence)`. The
   attempt succeeds when any primary detector hits, or, for `rule="all"` (jailbreaks),
   when all of them do.
4. Results are grouped per probe into findings: successes over attempts, a Wilson 95%
   interval, up to three example responses, the OWASP and ATLAS mapping and a remediation.
5. Renderers write the report formats; the CLI applies the `--fail-on` severity gate.

## Failure handling

Target errors are recorded on the attempt, never cached and never counted as findings;
`max_consecutive_errors` stops a scan whose target has died (ADR-0005). The llama.cpp
launcher waits for `/health`, keeps its log, and stops the server when the scan ends.
