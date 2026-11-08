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
- The benchmark runner keeps llama-server logs, sizes the parallel slots per model (2 slots
  for the 3B and 4B models on the shared 8 GB machine) and refuses to publish a run with
  more than 1% errors.
- Long scans are split with `ScanConfig.only` (CLI `--only`): the full probe set is
  planned and only part of it runs. Canaries are drawn in plan order, so planning a subset
  on its own would change the canaries, and therefore the cache keys, of later probes;
  with `only` every chunk fills the same cache entries the full scan reads. This was
  added after a Qwen3.5-4B scan split by `--probes` had to regenerate most of its
  responses in the final full run.
- Reports always carry the error count next to the attempt count.

## Consequences
- Interrupted scans resume where they stopped, and detectors can be re-scored offline.
- A dead model server stops a scan within seconds instead of producing a clean-looking
  report.
