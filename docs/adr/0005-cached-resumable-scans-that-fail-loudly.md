# ADR-0005: Cached, resumable scans that fail loudly on a dead target

- **Status:** Accepted
- **Date:** 2026-11-07

## Context
A full local scan takes 10 to 40 minutes on an 8 GB laptop and may be interrupted. A
first SmolLM2-1.7B run reported 539 errors in 540 attempts: llama-server had stopped
after the first request (its f16 KV cache for 4 slots of 4,096 tokens needs 3.2 GB on a
model without grouped-query attention) and every later request got "connection refused".
Errors are not findings, so that run looked like a model with almost nothing to report.

## Decision
- Responses are cached in an append-only JSONL file keyed by target, attempt digest,
  seed, temperature and token budget; errors are never cached, so a rerun retries them.
- `ScanConfig.max_consecutive_errors` (CLI `--max-consecutive-errors`, default 25) aborts
  the scan with `ScanAbortedError` when the target fails that many times in a row.
- The benchmark runner keeps llama-server logs, sizes the KV cache per model (2 slots of
  2,048 tokens for SmolLM2-1.7B) and refuses to publish a run with more than 1% errors.
- Reports always carry the error count next to the attempt count.

## Consequences
- Interrupted scans resume where they stopped, and detectors can be re-scored offline.
- A dead model server stops a scan within seconds instead of producing a clean-looking
  report.
