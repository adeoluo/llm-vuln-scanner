.PHONY: atlas-snapshot rescore help setup bench-setup lint format type test coverage rust-check rust-develop parity data models train-refusal scans demo-scans dataset-scans detectors garak speed ablations evaluation run demo-app diagram docker-build docker-up demo clean all changelog cut-release

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

models: ## Download the local models into the Hugging Face cache (about 11 GB; MODELS="qwen3.5-2b ..." for a subset)
	scripts/download_models.sh $(MODELS)

atlas-snapshot: ## Rewrite tests/data/atlas-2026.10-techniques.json from the ATLAS v2026.10 release asset
	uv run --no-sync --with pyyaml python scripts/atlas_snapshot.py --version 2026.10

train-refusal: ## Retrain the bundled refusal classifier on XSTest v2
	uv run --no-sync python benchmarks/train_refusal.py

scans: ## Full scans of the local models (writes benchmarks/results/scans/)
	cd benchmarks && for m in qwen3.5-0.8b qwen3.5-2b qwen3.5-4b gemma-4-e2b granite-4.2-3b; do uv run --no-sync python scan_models.py --model $$m || exit 1; done

demo-scans: ## Scan the demo application (vulnerable and hardened) backed by Qwen3.5-2B
	cd benchmarks && uv run --no-sync python scan_models.py --model demo-vulnerable && uv run --no-sync python scan_models.py --model demo-hardened

dataset-scans: ## Tensor Trust, Gandalf and in-the-wild jailbreak probes on Qwen3.5-2B (seeded samples of 150)
	cd benchmarks && uv run --no-sync python scan_models.py --model qwen3.5-2b --run qwen3.5-2b-datasets --probes dataset --sample 150

detectors: ## Refusal detectors against XSTest human labels (keyword, classifier, reference models, judge)
	cd benchmarks && uv run --no-sync python detectors.py

garak: ## garak on the same model (separate venv; see benchmarks/garak/README.md)
	cd benchmarks && uv run --no-sync python garak_compare.py

speed: ## Detector throughput, Rust versus Python
	cd benchmarks && uv run --no-sync python speed.py

rescore: ## Re-score every committed scan offline from the response cache (after a detector change)
	cd benchmarks && uv run --no-sync python rescore.py

ablations: ## Detector ablations re-scored on the stored scan responses
	cd benchmarks && uv run --no-sync python ablations.py

evaluation: ## Print the README tables from benchmarks/results/
	cd benchmarks && uv run --no-sync python report.py

run: ## Run the scanner HTTP service
	uv run python -m llm_vuln_scanner serve

demo-app: ## Run the deliberately vulnerable demo application (offline backend)
	uv run python -m llm_vuln_scanner demo-app

diagram: ## Render every diagram in docs/architecture to SVG (house theme, white background)
	@for f in docs/architecture/*.mmd; do \
		npx -y @mermaid-js/mermaid-cli -q -i "$$f" -o "$${f%.mmd}.svg" -c mermaid.config.json -b white || exit 1; \
	done

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

changelog: ## Regenerate CHANGELOG.md from Conventional Commits (git-cliff)
	git cliff --output CHANGELOG.md && perl -0pi -e 's/\n+\z/\n/' CHANGELOG.md

cut-release: ## Cut a release locally: version bump, changelog, tag, GitHub release (RELEASE_VERSION=vX.Y.Z optional)
	scripts/release.sh $(RELEASE_VERSION)
