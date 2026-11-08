# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

## Unreleased

### Features

- Probe catalog, detectors, targets, scan engine and reports (#2)
- Data scripts and a guard against dead model servers (#4)
- GitHub Action mode, refusal model tests and ADRs (#6)
- Detector, speed and garak comparison benchmarks
- Detector ablations and README table generator
- Full scans of Qwen2.5-1.5B and SmolLM2-1.7B, detector and ablation results
- Scan Qwen2.5-3B (Q3_K_M) and add an ablations target
- Demo application scans, vulnerable and hardened, on Qwen2.5-1.5B

### Bug fixes

- Include application documents in the response cache key (#7)
- Keep generation time when a scan is re-scored from the cache

### Performance

- Rust core for canary search, bit-parallel LCS and n-gram hashing (#3)
- ASCII fast path and allocation-free folding in the Rust skeleton (#8)

### Documentation

- Data card, model card and threat model
- Architecture diagram
- Scan and demo application recordings
- Comparison recording and a tighter demo application recording

### Build and CI

- Update actions to current majors and set the README header (#1)

### Maintenance

- Scaffold project
