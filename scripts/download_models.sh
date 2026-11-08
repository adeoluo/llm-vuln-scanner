#!/usr/bin/env bash
# Download the local models the benchmarks scan into the Hugging Face cache (no token needed).
#   Qwen2.5-1.5B-Instruct Q4_K_M GGUF (llama.cpp)          about 1.0 GB
#   SmolLM2-1.7B-Instruct Q4_K_M GGUF (llama.cpp)          about 1.0 GB
#   Qwen2.5-0.5B-Instruct safetensors (transformers)       about 1.0 GB
#   ProtectAI distilroberta-base-rejection-v1 (reference refusal classifier) about 0.3 GB
# llama-server comes from llama.cpp (brew install llama.cpp).
set -euo pipefail
HF="uvx --from huggingface_hub hf download"
$HF Qwen/Qwen2.5-1.5B-Instruct-GGUF qwen2.5-1.5b-instruct-q4_k_m.gguf
$HF HuggingFaceTB/SmolLM2-1.7B-Instruct-GGUF smollm2-1.7b-instruct-q4_k_m.gguf
$HF Qwen/Qwen2.5-0.5B-Instruct --include "*.json" "*.safetensors" "merges.txt" "vocab.json"
$HF ProtectAI/distilroberta-base-rejection-v1 --include "*.json" "*.safetensors" "merges.txt" "vocab.json"
