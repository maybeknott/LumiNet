# ============================================================================
# LumiNet — Build Orchestration
# ============================================================================
#
# Usage:
#   make build     — Full build (Rust → Go → Web → single binary)
#   make dev       — Development mode with hot reload
#   make test      — Run all tests
#   make lint      — Run all linters
#   make clean     — Clean build artifacts
#   make release   — Production build with optimizations
# ============================================================================

SHELL := /bin/bash

# ── Platform Detection ─────────────────────────────────────────────────────
ifeq ($(OS),Windows_NT)
    PLATFORM    := windows
    EXE_EXT     := .exe
    SHARED_EXT  := .dll
    SCRIPT_EXT  := .ps1
    RM          := powershell -Command "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"
    MKDIR       := powershell -Command "New-Item -ItemType Directory -Force"
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        PLATFORM   := darwin
        SHARED_EXT := .dylib
    else
        PLATFORM   := linux
        SHARED_EXT := .so
    endif
    EXE_EXT    :=
    SCRIPT_EXT := .sh
    RM         := rm -rf
    MKDIR      := mkdir -p
endif

# ── Paths ──────────────────────────────────────────────────────────────────
ROOT_DIR       := $(shell pwd)
RUST_DIR       := $(ROOT_DIR)/core
GO_DIR         := $(ROOT_DIR)/server
WEB_DIR        := $(ROOT_DIR)/web
BUILD_DIR      := $(ROOT_DIR)/build
RELEASE_DIR    := $(ROOT_DIR)/release
BIN_NAME       := luminet$(EXE_EXT)

# ── Rust Variables ─────────────────────────────────────────────────────────
RUST_LIB       := luminet_core$(SHARED_EXT)
RUST_HEADER    := luminet_core.h
CARGO_FLAGS    :=
CARGO_RELEASE  := --release

# ── Go Variables ───────────────────────────────────────────────────────────
GO_FLAGS       := -trimpath
GO_LDFLAGS     := -s -w
CGO_ENABLED    := 1

# ── Node Variables ─────────────────────────────────────────────────────────
NPM            := npx pnpm
NPM_FLAGS      :=

# ── Version ────────────────────────────────────────────────────────────────
VERSION        := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.0.0-dev")
COMMIT         := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE     := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_LDFLAGS     += -X github.com/maybeknott/luminet/cmd.Version=$(VERSION)

ifeq ($(PLATFORM),windows)
ifeq ($(GUI),1)
    GO_LDFLAGS += -H windowsgui
endif
endif

# ============================================================================
# Targets
# ============================================================================

.PHONY: all build dev test lint clean release help
.PHONY: build-rust build-go build-web
.PHONY: test-rust test-go test-web
.PHONY: lint-rust lint-go lint-web
.PHONY: generate-header

.DEFAULT_GOAL := help

## ── Full Build ────────────────────────────────────────────────────────────

all: build ## Alias for build

build: build-rust generate-header build-web build-go ## Full build pipeline
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo "  ✅ LumiNet build complete: $(BUILD_DIR)/$(BIN_NAME)"
	@echo "══════════════════════════════════════════════════════════════"

## ── Individual Build Targets ──────────────────────────────────────────────

build-rust: ## Build Rust core library
	@echo "🦀 Building Rust core..."
ifeq ($(PLATFORM),windows)
	cd $(RUST_DIR) && cargo build $(CARGO_RELEASE) $(CARGO_FLAGS) --target x86_64-pc-windows-gnu
	@$(MKDIR) $(RUST_DIR)/target/release 2>nul || true
	@$(MKDIR) $(RUST_DIR)/target/debug 2>nul || true
	@copy /y "$(subst /,ChangeSlash,$(RUST_DIR))\target\x86_64-pc-windows-gnu\release\liblumicore.a" "$(subst /,ChangeSlash,$(RUST_DIR))\target\release\liblumicore.a" >nul 2>nul || copy /y "$(subst /,ChangeSlash,$(RUST_DIR))\target\x86_64-pc-windows-gnu\debug\liblumicore.a" "$(subst /,ChangeSlash,$(RUST_DIR))\target\debug\liblumicore.a" >nul 2>nul || cp $(RUST_DIR)/target/x86_64-pc-windows-gnu/release/liblumicore.a $(RUST_DIR)/target/release/liblumicore.a 2>/dev/null || cp $(RUST_DIR)/target/x86_64-pc-windows-gnu/debug/liblumicore.a $(RUST_DIR)/target/debug/liblumicore.a 2>/dev/null || true
else
	cd $(RUST_DIR) && cargo build $(CARGO_RELEASE) $(CARGO_FLAGS)
endif
	@echo "   ✅ Rust core built"

generate-header: build-rust ## Generate C header from Rust FFI
	@echo "📝 Generating C header..."
	cd $(RUST_DIR) && cbindgen --config cbindgen.toml --crate lumicore --output ../$(RUST_HEADER)
	@echo "   ✅ Header generated: $(RUST_HEADER)"

build-web: ## Build web frontend
	@echo "⚛️  Building web frontend (Retired)..."
ifeq ($(PLATFORM),windows)
	@powershell -Command "New-Item -ItemType Directory -Force $(GO_DIR)/web/dist 2>nul; New-Item -ItemType File -Force $(GO_DIR)/web/dist/index.html -Value '<html><body>LumiNet Console Retired. Use Native GUI.</body></html>' 2>nul"
else
	@mkdir -p $(GO_DIR)/web/dist && echo "<html><body>LumiNet Console Retired. Use Native GUI.</body></html>" > $(GO_DIR)/web/dist/index.html
endif
	@echo "   ✅ Frontend built (Retired dummy console)"

build-go: build-rust generate-header ## Build Go server binary
	@echo "🐹 Building Go server..."
	@$(MKDIR) $(BUILD_DIR)
	cd $(GO_DIR) && CGO_ENABLED=$(CGO_ENABLED) go build \
		$(GO_FLAGS) \
		-ldflags "$(GO_LDFLAGS)" \
		-o $(BUILD_DIR)/$(BIN_NAME) \
		.
	@echo "   ✅ Go binary built: $(BUILD_DIR)/$(BIN_NAME)"

## ── Development ───────────────────────────────────────────────────────────

dev: ## Start development mode with hot reload
ifeq ($(PLATFORM),windows)
	@powershell -ExecutionPolicy Bypass -File ./scripts/dev.ps1
else
	@./scripts/dev.sh
endif

## ── Testing ───────────────────────────────────────────────────────────────

test: test-rust test-go ## Run all tests
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo "  ✅ All tests passed"
	@echo "══════════════════════════════════════════════════════════════"

test-rust: ## Run Rust tests
	@echo "🦀 Running Rust tests..."
	cd $(RUST_DIR) && cargo test $(CARGO_FLAGS)
	@echo "   ✅ Rust tests passed"

test-go: ## Run Go tests
	@echo "🐹 Running Go tests..."
	cd $(GO_DIR) && CGO_ENABLED=$(CGO_ENABLED) go test ./... -v -count=1
	@echo "   ✅ Go tests passed"

## ── Linting ───────────────────────────────────────────────────────────────

lint: lint-rust lint-go ## Run all linters
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo "  ✅ All linters passed"
	@echo "══════════════════════════════════════════════════════════════"

lint-rust: ## Run Rust linter (clippy)
	@echo "🦀 Linting Rust..."
	cd $(RUST_DIR) && cargo clippy $(CARGO_FLAGS) -- -D warnings
	cd $(RUST_DIR) && cargo fmt -- --check
	@echo "   ✅ Rust lint passed"

lint-go: ## Run Go linter
	@echo "🐹 Linting Go..."
	cd $(GO_DIR) && go vet ./...
	cd $(GO_DIR) && golangci-lint run ./...
	@echo "   ✅ Go lint passed"

## ── Clean ─────────────────────────────────────────────────────────────────

clean: ## Clean all build artifacts
	@echo "🧹 Cleaning build artifacts..."
	cd $(RUST_DIR) && cargo clean
	$(RM) $(BUILD_DIR)
	$(RM) $(RELEASE_DIR)
	$(RM) $(GO_DIR)/web/dist
	$(RM) $(RUST_HEADER)
	@echo "   ✅ Clean complete"

## ── Release ───────────────────────────────────────────────────────────────

release: ## Production build with optimizations
	@echo "🚀 Building release..."
	@$(MKDIR) $(RELEASE_DIR)
	$(MAKE) build CARGO_RELEASE="--release --locked" GO_FLAGS="-trimpath" NPM_FLAGS="--frozen-lockfile"
	@cp $(BUILD_DIR)/$(BIN_NAME) $(RELEASE_DIR)/$(BIN_NAME)
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo "  🚀 Release build: $(RELEASE_DIR)/$(BIN_NAME)"
	@echo "  📦 Version: $(VERSION)"
	@echo "  📋 Commit:  $(COMMIT)"
	@echo "══════════════════════════════════════════════════════════════"

## ── Help ──────────────────────────────────────────────────────────────────

help: ## Show this help
	@echo ""
	@echo "LumiNet Build System"
	@echo "────────────────────────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
