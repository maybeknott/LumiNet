SHELL := /bin/bash
.DEFAULT_GOAL := help
export PYTHONDONTWRITEBYTECODE := 1

ROOT_DIR := $(CURDIR)
RUST_DIR := $(ROOT_DIR)/src/packages/lumicore
SERVER_DIR := $(ROOT_DIR)/src/apps/daemon
DESKTOP_DIR := $(ROOT_DIR)/src/apps/desktop
FRONTEND_DIR := $(ROOT_DIR)/src/packages/control-ui
BUILD_DIR := $(ROOT_DIR)/build
RELEASE_DIR := $(ROOT_DIR)/release

ifeq ($(OS),Windows_NT)
PLATFORM := windows
EXE_EXT := .exe
else
PLATFORM := $(shell uname -s | tr '[:upper:]' '[:lower:]')
EXE_EXT :=
endif

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
PRESERVATION_BASE_SHA ?= $(shell git rev-parse HEAD^ 2>/dev/null || true)
BUILDINFO_PKG := github.com/maybeknott/luminet/contracts/buildinfo
GO_LDFLAGS := -s -w -X $(BUILDINFO_PKG).Version=$(VERSION) -X $(BUILDINFO_PKG).Commit=$(COMMIT) -X $(BUILDINFO_PKG).BuildDate=$(BUILD_DATE)

.PHONY: all build build-all build-rust build-go build-web build-desktop
.PHONY: test test-tooling test-rust test-go test-desktop test-web
.PHONY: lint lint-rust lint-go vet-go lint-web validate-abi validate-preservation audit-dependencies verify-repo verify-release contexts post-refactor-224-evidence post-refactor-225-evidence post-refactor-226-evidence post-refactor-227-evidence post-refactor-228-evidence post-refactor-229-evidence post-refactor-230-evidence post-refactor-231-evidence post-refactor-232-evidence graph inventory doctor clean release help

all: build

build: build-go ## Build the Rust core, canonical control UI, and Go daemon
	@printf '\nBuilt daemon: %s/luminet%s\n' "$(BUILD_DIR)" "$(EXE_EXT)"

build-all: build build-desktop ## Build daemon and desktop application

build-rust: ## Build the Rust core library
	cd "$(RUST_DIR)" && cargo build --release --locked

build-go: build-rust build-web ## Build the Go daemon and watchdog with current control UI
	mkdir -p "$(BUILD_DIR)"
	cd "$(SERVER_DIR)" && CGO_ENABLED=1 CGO_LDFLAGS="$$(python3 "$(ROOT_DIR)/scripts/checks/lumicore_link.py" --profile release --target x86_64-pc-windows-gnu)" go build -trimpath -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/luminet$(EXE_EXT)" .
	cd "$(SERVER_DIR)" && CGO_ENABLED=0 go build -trimpath -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/watchdog$(EXE_EXT)" ./cmd/watchdog

build-web: ## Install and build the React/Vite desktop frontend
	cd "$(FRONTEND_DIR)" && npm ci && npm run build

build-desktop: build-web ## Build the Wails desktop host with production frontend assets
	mkdir -p "$(BUILD_DIR)"
	cd "$(DESKTOP_DIR)" && go build -trimpath -o "$(BUILD_DIR)/luminet-desktop$(EXE_EXT)" .

test: test-rust test-go test-desktop test-web ## Run native, Go, desktop, and control-UI test suites

test-tooling: ## Run vendored repository-tooling module tests
	cd scripts && GOWORK=off GOPROXY=off go test -mod=vendor ./internal/... ./cmd/...

test-lumicore-sdk: ## Run the Python lumicore SDK unit tests (stdlib only)
	cd "$(ROOT_DIR)/src/packages/lumicore-sdk/python" && PYTHONPATH=. python3 -m unittest discover -s tests

test-rust: ## Run Rust tests
	cd "$(RUST_DIR)" && cargo test --locked

test-go: build-rust ## Run Go daemon tests with and without CGO
	cd "$(SERVER_DIR)" && CGO_ENABLED=1 CGO_LDFLAGS="$$(python3 "$(ROOT_DIR)/scripts/checks/lumicore_link.py" --profile release --target x86_64-pc-windows-gnu)" go test ./... -count=1
	cd "$(SERVER_DIR)" && CGO_ENABLED=0 go test ./... -count=1

test-desktop: ## Run Wails bridge tests (frontend bundle is not required)
	cd "$(DESKTOP_DIR)" && go test ./... -count=1

test-web: ## Install, test, lint, audit, type-check, and bundle the frontend
	cd "$(FRONTEND_DIR)" && npm ci && npm run audit && npm test && npm run lint && npm run build

lint: lint-rust lint-go lint-web ## Run all configured linters

lint-rust: ## Check Rust formatting and Clippy
	cd "$(RUST_DIR)" && cargo fmt -- --check
	cd "$(RUST_DIR)" && cargo clippy --locked --all-targets -- -D warnings

vet-go: build-rust ## Run Go vet against the linked host and desktop modules
	cd "$(SERVER_DIR)" && CGO_ENABLED=1 CGO_LDFLAGS="$$(python3 "$(ROOT_DIR)/scripts/checks/lumicore_link.py" --profile release --target x86_64-pc-windows-gnu)" go vet ./...
	cd "$(DESKTOP_DIR)" && go vet ./...

lint-go: vet-go ## Run Go formatting and vet checks
	@test -z "$$(gofmt -l $$(find src/apps/desktop src/apps/daemon tests -name '*.go' -type f))"

lint-web: ## Run the frontend linter
	cd "$(FRONTEND_DIR)" && npm run lint

validate-abi: ## Validate the checked ABI manifest against Rust authority
	cd scripts && GOWORK=off GOPROXY=off go run -mod=vendor ./cmd/validate-abi-manifest -repo-root ..

validate-preservation: ## Validate repository changes against the preservation ledger
	@test -n "$(PRESERVATION_BASE_SHA)" || (echo "PRESERVATION_BASE_SHA is required for release admission" >&2; exit 1)
	cd scripts && GOWORK=off GOPROXY=off PRESERVATION_BASE_SHA="$(PRESERVATION_BASE_SHA)" go run -mod=vendor ./cmd/validate-preservation-ledger -repo-root .. -mode ci

audit-dependencies: ## Audit Go and Rust dependency reachability against vulnerability databases
	command -v govulncheck >/dev/null || (echo "govulncheck is required for release admission" >&2; exit 1)
	cd "$(SERVER_DIR)" && govulncheck ./...
	cd "$(DESKTOP_DIR)" && govulncheck ./...
	cd "$(ROOT_DIR)/src/packages/contracts" && govulncheck ./...
	cd "$(ROOT_DIR)/src/packages/control-ui" && govulncheck ./...
	cd "$(RUST_DIR)" && cargo audit

verify-repo: ## Check repository structure, topology, convergence evidence, and toolchain declarations
	python3 scripts/checks/check_source_structure.py
	python3 scripts/checks/check_source_context.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_tooling_surface.py
	python3 scripts/checks/verify_repository_topology.py
	python3 scripts/checks/check_lumicore_source_purity.py
	python3 scripts/checks/check_daemon_reachability.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_desktop_reachability.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mobile_tun_ownership.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mobile_binding.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mobile_adapter_parity.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mobile_product.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_host_products.py
	GOWORK=off GOTOOLCHAIN=local go run scripts/checks/check_go_target_selection.go
	GOWORK=off GOTOOLCHAIN=local go run scripts/checks/check_go_declaration_integrity.go
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_daemon_lifecycle.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_request_context.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_host_network_ownership.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_runtime_core_ownership.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_proxy_facade_ownership.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_dormant_surface_pruning.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_scanner_liveness.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_telemetry_truth.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_job_contract_ownership.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_evasion_truth.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_advanced_capability_truth.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_per_app_capability_truth.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_advanced_runtime_pruning.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_subscription_ownership.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_subscription_pruning.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_remote_http_actions.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_second_order_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_third_wave_runtime.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_third_wave_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_fourth_order_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_fifth_order_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_sixth_order_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_seventh_order_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_eighth_order_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_ninth_order_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_final_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_ultimate_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_refactor_audit.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_83_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_97_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_117_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_137_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_api_direct_client_ip.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_141_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_160_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_180_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_220_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_222_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_android.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_command_aliases.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_dns_integrity.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_native_async.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_raw_ffi.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_subscription_catalogue.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_subscription_nodes_ui.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_subscription_runtime_api.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_223_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_224_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_225_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_226_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_227_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_228_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_229_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_230_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_231_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_232_convergence.py
	LUMINET_233_WORK_ROOT=/mnt/data/luminet233_work PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_233_convergence.py
	LUMINET_234_WORK_ROOT=/mnt/data/luminet234 PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_234_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_235_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_236_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_route_truth.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_platform_capability_truth.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_native_degraded_truth.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_proxy_liveness.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_final_pruning.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_proxy_qualification.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_lumicore_abi.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_rust_ffi_refactor.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_ffi_runtime_safety.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_ffi_dead_surface.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_native_dormant_surfaces.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_native_verification_coverage.py
	cd scripts/checks && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -q test_lumicore_link.py
	python3 scripts/checks/validate_convergence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_peer_convergence.py
	python3 scripts/checks/repo_audit.py

verify-release: test-tooling test-lumicore-sdk validate-abi validate-preservation verify-repo audit-dependencies lint-rust test-rust vet-go test-go test-desktop test-web ## Run the canonical release-admission verification suite
	@printf '\nRelease admission verification passed.\n'


contexts: ## Regenerate source-folder .context navigation files
	python3 scripts/generate/generate_source_context.py
	python3 scripts/checks/check_source_context.py

post-refactor-224-evidence: ## Regenerate the post-refactor-224 donor evidence matrices from mounted immutable donor archives
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_224_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_224_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_224_convergence.py

post-refactor-225-evidence: ## Regenerate post-refactor-225 current-wave, all-history, baseline, and delta evidence
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_225_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_225_all_history_audit.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_225_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_225_convergence.py

post-refactor-226-evidence: ## Regenerate post-refactor-226 current-wave, all-history, frozen-baseline delta, and convergence evidence
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_226_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_226_all_history_audit.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_226_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_226_convergence.py

post-refactor-227-evidence: ## Regenerate post-refactor-227 current-wave, all-history, frozen-baseline delta, and convergence evidence
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_227_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_227_all_history_audit.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_227_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_227_convergence.py

post-refactor-228-evidence: ## Re-audit all 226/227 raw donors, regenerate second-order evidence/delta, and verify retry/convergence authority
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_228_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_228_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_228_convergence.py

post-refactor-229-evidence: ## Regenerate post-refactor-229 five-donor + nested-source evidence, frozen-baseline delta, and convergence checks
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_229_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_229_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_229_convergence.py

post-refactor-230-evidence: ## Regenerate post-refactor-230 thirteen-donor evidence, frozen-baseline delta, and convergence checks
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_230_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_230_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_230_convergence.py

inventory: ## Rebuild an inventory for the current working tree
	python3 scripts/generate/repo_inventory.py --root . --output docs/audit/current-inventory

graph: ## Generate a Graphify knowledge graph (requires graphifyy)
	./scripts/graphify.sh

doctor: ## Show required toolchain availability
	@printf 'Go: '; command -v go >/dev/null && go version || echo missing
	@printf 'Rust: '; command -v cargo >/dev/null && cargo --version || echo missing
	@printf 'Node: '; command -v node >/dev/null && node --version || echo missing
	@printf 'npm: '; command -v npm >/dev/null && npm --version || echo missing
	@printf 'Java: '; command -v java >/dev/null && java -version 2>&1 | head -1 || echo missing
	@printf 'Gradle: '; command -v gradle >/dev/null && gradle --version | head -1 || echo missing
	@printf 'Graphify: '; command -v graphify >/dev/null && graphify --version || echo missing

clean: ## Remove local build outputs without deleting dependencies
	rm -rf "$(BUILD_DIR)" "$(RELEASE_DIR)" "$(FRONTEND_DIR)/dist"
	mkdir -p "$(FRONTEND_DIR)/dist" && touch "$(FRONTEND_DIR)/dist/.gitkeep"
	cd "$(RUST_DIR)" && cargo clean

release: verify-release ## Create optimized local release binaries
	$(MAKE) build-all
	mkdir -p "$(RELEASE_DIR)"
	cp "$(BUILD_DIR)/luminet$(EXE_EXT)" "$(RELEASE_DIR)/"
	cp "$(BUILD_DIR)/watchdog$(EXE_EXT)" "$(RELEASE_DIR)/"
	cp "$(BUILD_DIR)/luminet-desktop$(EXE_EXT)" "$(RELEASE_DIR)/"

help: ## Show available targets
	@printf '\nLumiNet build targets\n\n'
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*## "}; {printf "  %-20s %s\n", $$1, $$2}'
	@printf '\n'

post-refactor-231-evidence:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_231_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_231_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_231_convergence.py

post-refactor-232-evidence: ## Regenerate post-refactor-232 four-donor evidence, frozen-baseline delta, retry authority, and convergence checks
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_232_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_232_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_232_convergence.py

.PHONY: post-refactor-233-evidence
post-refactor-233-evidence:
	LUMINET_233_WORK_ROOT=/mnt/data/luminet233_work PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_233_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_233_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	LUMINET_233_WORK_ROOT=/mnt/data/luminet233_work PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_233_convergence.py

.PHONY: post-refactor-234-evidence
post-refactor-234-evidence:
	LUMINET_234_WORK_ROOT=/mnt/data/luminet234 PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_234_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_234_delta.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	LUMINET_234_WORK_ROOT=/mnt/data/luminet234 PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_234_convergence.py

post-refactor-235-evidence:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_235_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_235_convergence.py

post-refactor-236-evidence:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate/generate_post_refactor_236_evidence.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_mutation_retry_authority.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_post_refactor_236_convergence.py
