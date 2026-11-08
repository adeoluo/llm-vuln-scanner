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

## Residual risk
Scans are a lower bound: a passing report does not prove the absence of vulnerabilities.
Detector false negatives are measured where labels exist (XSTest) and discussed in the
evaluation report.
