#!/usr/bin/env bash
# Download the local models the benchmarks use into the Hugging Face cache (no token needed).
# GGUF builds for llama.cpp (llama-server from brew install llama.cpp, b9.0 or later):
#   Qwen3.5-0.8B Q4_K_M         unsloth/Qwen3.5-0.8B-GGUF                 0.53 GB
#   Qwen3.5-2B Q4_K_M           unsloth/Qwen3.5-2B-GGUF                   1.28 GB
#   Qwen3.5-4B Q3_K_M           unsloth/Qwen3.5-4B-GGUF                   2.29 GB
#   gemma-4-E2B-it Q4_0 (QAT)   google/gemma-4-E2B-it-qat-q4_0-gguf       3.35 GB
#   granite-4.2-3b Q4_K_M       ibm-granite/granite-4.2-3b-GGUF           2.24 GB
# Reference detectors (transformers):
#   Qwen3Guard-Gen-0.6B         Qwen/Qwen3Guard-Gen-0.6B                  1.50 GB
#   distilroberta-base-rejection-v1  ProtectAI/distilroberta-base-rejection-v1  0.33 GB
# Pass model keys to fetch a subset (for example: scripts/download_models.sh qwen3.5-2b),
# and remove a GGUF after its scan with: hf cache delete (the scans need one at a time).
set -euo pipefail
HF="uvx --from huggingface_hub hf download"
fetch() {
  local key=$1; shift
  if [ ${#SELECTED[@]} -eq 0 ] || [[ " ${SELECTED[*]} " == *" $key "* ]]; then $HF "$@"; fi
}
SELECTED=("$@")
fetch qwen3.5-0.8b unsloth/Qwen3.5-0.8B-GGUF Qwen3.5-0.8B-Q4_K_M.gguf
fetch qwen3.5-2b unsloth/Qwen3.5-2B-GGUF Qwen3.5-2B-Q4_K_M.gguf
fetch qwen3.5-4b unsloth/Qwen3.5-4B-GGUF Qwen3.5-4B-Q3_K_M.gguf
fetch gemma-4-e2b google/gemma-4-E2B-it-qat-q4_0-gguf gemma-4-E2B_q4_0-it.gguf
fetch granite-4.2-3b ibm-granite/granite-4.2-3b-GGUF granite-4.2-3b-Q4_K_M.gguf
fetch qwen3guard Qwen/Qwen3Guard-Gen-0.6B --include "*.json" "*.safetensors" "merges.txt" "vocab.json"
fetch protectai ProtectAI/distilroberta-base-rejection-v1 --include "*.json" "*.safetensors" "merges.txt" "vocab.json"
