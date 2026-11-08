# Threat Model: LLM Vuln Scanner

Two systems are in scope: the scanner itself (CLI, HTTP service, GitHub Action) and the
deliberately vulnerable demo application shipped for testing it.

## Assets
- API keys of scanned endpoints (read from an environment variable named on the command line).
- The machine running scans (sink detectors handle attacker-influenced model output).
- Scan reports (they contain model outputs, which may include leaked canaries).
- CI integrity when used as a GitHub Action (SARIF upload, pass/fail gate).

## Trust boundaries
1. Target responses are untrusted: they are model output steered by adversarial prompts.
2. Application profiles and dataset files are semi-trusted inputs chosen by the user.
3. The HTTP service accepts scan requests from the network.

## Threats

| Threat | Vector | Impact | Mitigation |
|---|---|---|---|
| Code execution through sink detectors | Model output with SQL, shell or HTML payloads | Compromise of the scanning host | SQL runs only in an in-memory SQLite database with an allow-list authorizer that permits only reads, plus a step limit; shell output is tokenized with `shlex`, never executed; HTML is parsed, never rendered |
| Report injection | Output containing HTML or script lands in the HTML report | XSS for whoever opens the report | Every response is HTML-escaped in the report; SARIF and JUnit are generated with JSON and XML encoders |
| Secret leakage | API key in logs or reports | Credential theft | Keys are read from a named environment variable and only sent in the Authorization header; never logged or written to reports |
| Server-side request forgery | HTTP service asked to scan arbitrary URLs | Internal network probing | The service only accepts targets matching `--allow-target` prefixes (default: simulated models) and caps scan size |
| Resource exhaustion | Token blow-up probes, huge responses | Slow or stuck scans | Per-attempt token budgets, request timeouts, retries with backoff, abort after consecutive errors |
| Misleading results | Dead target recorded as "no findings" | False assurance | Errors are counted separately, never cached, and abort the scan after 25 in a row (ADR-0005) |
| Demo app misuse | Running the vulnerable app on a public interface | Real exposure | Binds to 127.0.0.1 by default; secrets are fictional; documentation marks it as vulnerable |
| Supply chain | Malicious dependency | Code execution | Minimal runtime dependencies (numpy), `uv.lock`, CodeQL on main |

## Risks the probes test in a scanned application
The scanner's own threat model is above; what it looks for in a target follows the OWASP
Top 10 for LLM Applications 2026, the OWASP Top 10 for Agentic Applications 2026 and
MITRE ATLAS v2026.10 (full mapping in ADR-0007, `llm-vuln-scanner taxonomy`).

| OWASP LLM 2026 | Probes | OWASP Agentic 2026 | ATLAS v2026.10 |
|---|---|---|---|
| LLM01 Prompt Injection | `injection.*`, `encoding.obfuscation`, `jailbreak.templates`, `dataset.tensortrust_hijacking`, `dataset.wild_jailbreak` | | AML.T0051, AML.T0068, AML.T0054, AML.T0070 |
| LLM02 Sensitive Information Disclosure | `disclosure.secrets` | | AML.T0085.002, AML.T0055 |
| LLM03 Excessive Agency | `agency.tools` | ASI01, ASI02 | AML.T0053, AML.T0086, AML.T0101 |
| LLM06 Unbounded Consumption | `dos.token_blowup` | | AML.T0029, AML.T0034.001 |
| LLM08 Hidden Context Exposure | `leakage.system_prompt`, `dataset.tensortrust_extraction`, `dataset.gandalf` | | AML.T0085.003, AML.T0069.002 |
| LLM10 Improper Output Handling | `output.xss`, `output.sql`, `output.shell` | ASI05 (`output.shell`) | AML.T0077, AML.T0050 |

LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM07 Misinformation and LLM09 Vector
and Embedding Weaknesses are out of scope for black-box prompts.

### NIST
A scan is evidence for NIST AI RMF 1.0 MEASURE 2.7 (security and resilience are evaluated
and documented) and MANAGE 2.4 (mechanisms to supersede or deactivate a system that does
not perform as intended: the `--fail-on` gate). In the Generative AI Profile (NIST AI 600-1,
July 2024) the probes cover the Information Security risk (prompt injection, output
handling, agency, token blow-up), Data Privacy (`disclosure.secrets`) and Human-AI
Configuration (unconfirmed high-impact tool calls in `agency.tools`). In the adversarial ML
taxonomy NIST AI 100-2 E2025 (March 2025, the current edition), they are direct prompting
attacks (`injection.direct`, `encoding.obfuscation`, `jailbreak.templates`, prompt
extraction in `leakage.system_prompt`), indirect prompt injection (`injection.indirect`,
`agency.tools`), and the privacy compromise and availability breakdown objectives
(`disclosure.secrets`, `dos.token_blowup`).

## Residual risk
Scans are a lower bound: a passing report does not prove the absence of vulnerabilities.
Detector false negatives are measured where labels exist (XSTest) and discussed in the
evaluation report.
