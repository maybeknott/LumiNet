#!/usr/bin/env bash
# ============================================================================
# LumiNet — Full Build Script (Linux / macOS)
# ============================================================================
#
# Usage:
#   ./scripts/build-all.sh              # Release build
#   ./scripts/build-all.sh --debug      # Debug build
#   ./scripts/build-all.sh --skip-web   # Skip frontend
# ============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
CONFIGURATION="release"
SKIP_WEB=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)      CONFIGURATION="debug"; shift ;;
        --skip-web)   SKIP_WEB=true; shift ;;
        --verbose)    VERBOSE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--debug] [--skip-web] [--verbose]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Paths ──────────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$ROOT_DIR/core"
SERVER_DIR="$ROOT_DIR/server"
WEB_DIR="$ROOT_DIR/web"
BUILD_DIR="$ROOT_DIR/build"
BIN_NAME="luminet"
HEADER_FILE="$ROOT_DIR/luminet_core.h"

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
RESET='\033[0m'

# ── Helpers ────────────────────────────────────────────────────────────────

step_header() {
    local emoji="$1"
    local message="$2"
    echo ""
    echo -e "${DIM}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "  ${CYAN}${emoji} ${message}${RESET}"
    echo -e "${DIM}══════════════════════════════════════════════════════════════${RESET}"
}

success() {
    echo -e "  ${GREEN}✅ $1${RESET}"
}

fail() {
    echo -e "  ${RED}❌ FAILED: $1${RESET}"
    exit 1
}

assert_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "  ${RED}❌ Required command not found: $1${RESET}"
        echo -e "     Please install $1 and ensure it is on your PATH."
        exit 1
    fi
}

elapsed_since() {
    local start="$1"
    local now
    now=$(date +%s)
    local diff=$((now - start))
    echo -e "  ${DIM}⏱  Completed in ${diff}s${RESET}"
}

# ── Determine shared library extension ─────────────────────────────────────
case "$(uname -s)" in
    Darwin*) SHARED_EXT=".dylib" ;;
    *)       SHARED_EXT=".so" ;;
esac

# ── Preamble ───────────────────────────────────────────────────────────────
TOTAL_START=$(date +%s)

echo ""
echo -e "  ${MAGENTA}🌐 LumiNet Build System${RESET}"
echo -e "     ${DIM}Configuration: ${CONFIGURATION}${RESET}"
echo -e "     ${DIM}Platform:      $(uname -s) ($(uname -m))${RESET}"
echo ""

# ── Prerequisite Checks ───────────────────────────────────────────────────
step_header "🔍" "Checking prerequisites..."
assert_command "cargo"
assert_command "cbindgen"
assert_command "go"
if [ "$SKIP_WEB" = false ]; then
    assert_command "pnpm"
    assert_command "node"
fi
success "All prerequisites found"

# ── Step 1: Build Rust Core ───────────────────────────────────────────────
step_header "🦀" "Step 1/4 — Building Rust core library"
STEP_START=$(date +%s)

cargo_args=("build")
if [ "$CONFIGURATION" = "release" ]; then
    cargo_args+=("--release")
fi
if [ "$VERBOSE" = true ]; then
    cargo_args+=("--verbose")
fi

(cd "$CORE_DIR" && cargo "${cargo_args[@]}") || fail "Rust build"
elapsed_since "$STEP_START"
success "Rust core library built"

# ── Step 2: Generate C Header ─────────────────────────────────────────────
step_header "📝" "Step 2/4 — Generating C header (cbindgen)"
STEP_START=$(date +%s)

(cd "$CORE_DIR" && cbindgen --config cbindgen.toml --crate lumicore --output "$HEADER_FILE") \
    || fail "cbindgen header generation"

elapsed_since "$STEP_START"
success "C header generated: $HEADER_FILE"

# ── Step 3: Build Web Frontend ────────────────────────────────────────────
if [ "$SKIP_WEB" = true ]; then
    step_header "⏭️" "Step 3/4 — Skipping web frontend (--skip-web)"
else
    step_header "⚛️" "Step 3/4 — Building web frontend"
    STEP_START=$(date +%s)

    (cd "$WEB_DIR" && pnpm install --frozen-lockfile) || fail "Frontend install"
    (cd "$WEB_DIR" && pnpm run build) || fail "Frontend build"

    elapsed_since "$STEP_START"
    success "Web frontend built"
fi

# ── Step 4: Build Go Server ───────────────────────────────────────────────
step_header "🐹" "Step 4/4 — Building Go server binary"
STEP_START=$(date +%s)

mkdir -p "$BUILD_DIR"

# Version info
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "v0.0.0-dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

(cd "$SERVER_DIR" && \
    CGO_ENABLED=1 go build \
        -trimpath \
        -ldflags "$LDFLAGS" \
        -o "$BUILD_DIR/$BIN_NAME" \
        .) \
    || fail "Go build"

elapsed_since "$STEP_START"
success "Go binary built: $BUILD_DIR/$BIN_NAME"

# ── Summary ────────────────────────────────────────────────────────────────
TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${RESET}"
echo -e "  ${GREEN}🎉 BUILD SUCCESSFUL${RESET}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${RESET}"
echo -e "  Binary:  $BUILD_DIR/$BIN_NAME"
echo -e "  Config:  $CONFIGURATION"
echo -e "  Time:    $((TOTAL_ELAPSED / 60))m $((TOTAL_ELAPSED % 60))s"
echo ""
