#!/usr/bin/env bash
# Download the public datasets used by the dataset probes and the detector benchmark
# (about 6 MB in total) into DIR (default ../.bench-data/llm-vuln-scanner/data).
#   Tensor Trust robustness benchmarks (Toyer et al., 2023): 775 hijacking + 569 extraction
#   Lakera gandalf_ignore_instructions: 1,000 prompts (777 train, 111 validation, 112 test)
#   TrustAIRLab in-the-wild jailbreak prompts, 2023-12-25 snapshot: 1,405 prompts
#   XSTest v2 completions with human labels (Rottger et al., 2024): 5 models x 450 prompts
set -euo pipefail
DIR="${1:-../.bench-data/llm-vuln-scanner/data}"
mkdir -p "$DIR"
fetch() { [ -s "$DIR/$2" ] || curl -fsSL --retry 3 -o "$DIR/$2" "$1"; echo "  $2 $(wc -c < "$DIR/$2" | tr -d ' ') bytes"; }

TT=https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/main/benchmarks
fetch "$TT/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl" tt_hijacking.jsonl
fetch "$TT/extraction-robustness/v1/extraction_robustness_dataset.jsonl" tt_extraction.jsonl

G=https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions/resolve/main/data
fetch "$G/train-00000-of-00001-ded53be747ff55cd.parquet" gandalf_train.parquet
fetch "$G/validation-00000-of-00001-94481a2a09ff2fff.parquet" gandalf_validation.parquet
fetch "$G/test-00000-of-00001-bc92128b9288a6d1.parquet" gandalf_test.parquet

W=https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts/resolve/main
fetch "$W/jailbreak_2023_12_25/train-00000-of-00001.parquet" wild_jailbreak_2023_12_25.parquet

X=https://raw.githubusercontent.com/paul-rottger/xstest/main
for m in gpt4 llama2new llama2orig mistralguard mistralinstruct; do
  fetch "$X/model_completions/xstest_v2_completions_$m.csv" "xstest_xstest_v2_completions_$m.csv"
done
fetch "$X/LICENSE" xstest_LICENSE
