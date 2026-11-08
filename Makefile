.PHONY: help setup bench-setup lint format type test coverage rust-check rust-develop parity data models train-refusal scans demo-scans dataset-scans detectors garak speed evaluation run demo-app diagram docker-build docker-up demo clean all changelog cut-release

BENCH ?= ../.bench-data/llm-vuln-scanner

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies (compiles the Rust core) and pre-commit hooks
	uv sync --dev --group validation
	uv run pre-commit install

bench-setup: ## Everything the full-scale benchmarks need (transformers, scikit-learn, pyarrow)
	uv sync --dev --group validation --group data --extra transformers

format: ## Format automatically
	uv run ruff format .
	uv run ruff check --fix .

lint: ## Lint (no fixes)
	uv run ruff format --check .
	uv run ruff check .

type: ## Type-check
	uv run mypy src

test: ## Run tests
	uv run pytest

coverage: ## Tests with the coverage gate used in CI
	LVS_REQUIRE_RUST=1 uv run pytest --cov=src --cov-report=term-missing --cov-fail-under=80

rust-check: ## Rust core: fmt, clippy (with and without Python), unit tests
	cd rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --features python -- -D warnings && cargo test

rust-develop: ## Rebuild the Rust core into .venv after editing rust/
	uv sync --group rust
	uv run --no-sync maturin develop --uv --release

parity: ## Rust versus Python parity tests
	LVS_REQUIRE_RUST=1 uv run --no-sync pytest tests/test_parity.py -v

data: ## Download the public datasets (about 6 MB, outside the repository)
	scripts/download_data.sh $(BENCH)/data
	uv run --group data python scripts/prepare_data.py --data $(BENCH)/data

models: ## Download the GGUF models into the Hugging Face cache (about 2.2 GB)
	scripts/download_models.sh

train-refusal: ## Retrain the bundled refusal classifier on XSTest v2
	uv run --no-sync python benchmarks/train_refusal.py

scans: ## Full scans of the local models (writes benchmarks/results/scans/)
	cd benchmarks && for m in qwen2.5-1.5b smollm2-1.7b qwen2.5-0.5b; do uv run --no-sync python scan_models.py --model $$m || exit 1; done

demo-scans: ## Scan the demo application (vulnerable and hardened) backed by Qwen2.5-1.5B
	cd benchmarks && uv run --no-sync python scan_models.py --model demo-vulnerable && uv run --no-sync python scan_models.py --model demo-hardened

dataset-scans: ## Tensor Trust, Gandalf and in-the-wild jailbreak probes on Qwen2.5-1.5B
	cd benchmarks && uv run --no-sync python scan_models.py --model qwen2.5-1.5b --run qwen2.5-1.5b-datasets --probes dataset

detectors: ## Refusal detectors against XSTest human labels (keyword, classifier, reference model, judge)
	cd benchmarks && uv run --no-sync python detectors.py

garak: ## garak on the same model (separate venv; see benchmarks/garak/README.md)
	cd benchmarks && uv run --no-sync python garak_compare.py

speed: ## Detector throughput, Rust versus Python
	cd benchmarks && uv run --no-sync python speed.py

evaluation: ## Print the README tables from benchmarks/results/
	cd benchmarks && uv run --no-sync python report.py

run: ## Run the scanner HTTP service
	uv run python -m llm_vuln_scanner serve

demo-app: ## Run the deliberately vulnerable demo application (offline backend)
	uv run python -m llm_vuln_scanner demo-app

diagram: ## Render the architecture diagram to SVG
	npx -y @mermaid-js/mermaid-cli -i docs/architecture/architecture.mmd \
	     -o docs/architecture/architecture.svg \
	     -c mermaid.config.json -b transparent

docker-build: ## Build the image
	docker build -t llm-vuln-scanner .

docker-up: ## Scanner service and demo application via docker compose
	docker compose up --build

demo: ## Record the demo GIFs with vhs
	for t in docs/demo/*.tape; do vhs $$t; done

clean: ## Remove caches and artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info coverage.xml rust/target reports
	find . -type d -name __pycache__ -exec rm -rf {} +

all: lint type coverage ## Full local gate (mirror of continuous integration)
