# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

## [0.1.0] 2026-11-08

### Features

- Probe catalog, detectors, targets, scan engine and reports (#2)
- Data scripts and a guard against dead model servers (#4)
- GitHub Action mode, refusal model tests and ADRs (#6)
- Full-scale benchmarks, results, docs and release tooling (#5)
- LLM judge benchmark, Rust speed results and module map (#10)
- Map probes and reports to OWASP LLM Top 10 2026, OWASP Agentic Top 10 2026 and ATLAS v2026.10 (#11)
- Scans of Qwen3.5-0.8B and Qwen3.5-2B and the demo application on Qwen3.5-2B (#13)
- Garak 0.17.1 comparison and refusal detector results on current models (#14)
- Split long scans into chunks that share the full scan's attempts (#15)
- Qwen3.5-4B scan and a fix for reading non-scan results in the report script (#16)
- Gemma-4-E2B-it and granite-4.2-3b scans (#17)
- Dataset probes, detector ablations and a stricter jailbreak rule (#18)

### Bug fixes

- Include application documents in the response cache key (#7)

### Performance

- Rust core for canary search, bit-parallel LCS and n-gram hashing (#3)
- ASCII fast path and allocation-free folding in the Rust skeleton (#8)

### Documentation

- Verify every number against benchmarks/results and fix the test count and scan times (#19)

### Build and CI

- Update actions to current majors and set the README header (#1)
- Release wheels workflow and the garak any-detector rule (#9)
- Python 3.12 to 3.15, Rust edition 2024 and current tool versions (#12)

### Maintenance

- Scaffold project
