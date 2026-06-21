#!/usr/bin/env bash

set -euo pipefail

# Default parameters
PORT=5173
API_PORT=8990
SKIP_RUST_WATCH=false
SKIP_WEB=false

# Helper for banners
print_banner() {
    echo -e "\033[1;35m"
    echo "  🌐 LumiNet Development Mode"
    echo "  ───────────────────────────────────────"
    echo "  Frontend:  http://localhost:${PORT}"
    echo "  API:       http://localhost:${API_PORT}"
    echo "  ───────────────────────────────────────"
    echo "  Press Ctrl+C to stop all processes"
    echo -e "\033[0m"
}

assert_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "\033[0;31m  ❌ Required: $1\033[0m"
        if [ -n "$2" ]; then
            echo -e "\033[0;33m     Install: $2\033[0m"
        fi
        exit 1
    fi
}

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$ROOT_DIR/core"
SERVER_DIR="$ROOT_DIR/server"
WEB_DIR="$ROOT_DIR/web"

# Prerequisite Checks
assert_command "go" "https://go.dev/dl/"
assert_command "air" "go install github.com/air-verse/air@latest"
if [ "$SKIP_WEB" = false ]; then
    assert_command "pnpm" "npm install -g pnpm"
    assert_command "node" "https://nodejs.org/"
fi
if [ "$SKIP_RUST_WATCH" = false ]; then
    assert_command "cargo" "https://rustup.rs/"
    assert_command "cargo-watch" "cargo install cargo-watch"
fi

# Track PIDs for cleanup
PIDS=()

cleanup() {
    echo ""
    echo -e "\033[0;33m  🛑 Shutting down dev processes...\033[0m"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            echo -e "\033[0;90m     Stopped PID $pid\033[0m"
        fi
    done
    echo -e "\033[0;32m  ✅ All processes stopped\033[0m"
}

# Set up trap for exit/sigint/sigterm
trap cleanup EXIT INT TERM

# ── Initial Rust Build ────────────────────────────────────────────────────
echo -e "\033[0;36m  🦀 Building Rust core (initial)...\033[0m"
(cd "$CORE_DIR" && cargo build && cbindgen --config cbindgen.toml --crate lumicore --output ../luminet_core.h)
echo -e "\033[0;32m  ✅ Rust core ready\033[0m"

# ── Start Vite Dev Server ─────────────────────────────────────────────────
if [ "$SKIP_WEB" = false ]; then
    echo -e "\033[0;36m  ⚛️  Starting Vite dev server on :$PORT...\033[0m"
    (cd "$WEB_DIR" && pnpm run dev -- --port "$PORT") &
    PIDS+=($!)
fi

# ── Start Go Server with Air ──────────────────────────────────────────────
echo -e "\033[0;36m  🐹 Starting Go server with air on :$API_PORT...\033[0m"
export LUMINET_PORT=$API_PORT
export LUMINET_DEV=true
export CGO_ENABLED=1
(cd "$SERVER_DIR" && air -c .air.toml) &
PIDS+=($!)

# ── Start Rust File Watcher ───────────────────────────────────────────────
if [ "$SKIP_RUST_WATCH" = false ]; then
    echo -e "\033[0;36m  🦀 Starting Rust file watcher...\033[0m"
    (cd "$CORE_DIR" && cargo watch -w src -s "cargo build && cbindgen --config cbindgen.toml --crate lumicore --output ../luminet_core.h") &
    PIDS+=($!)
fi

print_banner

# Wait for background jobs to finish or exit
wait
