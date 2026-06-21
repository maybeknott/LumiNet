#!/bin/bash
# LumiNet Native Mobile Library Compilation Orchestrator

# Set error handling
set -e

# Output folder
OUT_DIR="build/mobile"
mkdir -p "$OUT_DIR"

echo "Checking requirements..."

# Check Go
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed or not in PATH."
    exit 1
fi

# Check gomobile
if ! command -v gomobile &> /dev/null; then
    echo "ERROR: gomobile is not installed or not in PATH."
    echo "Please run: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init"
    exit 1
fi

echo "Requirements check passed."
echo "Starting compilation..."

# Target package directory is server/internal/proxy
TARGET_PKG="./server/internal/proxy"

# Android Build
echo "Building Android AAR library..."
# Standard compilation target: arm, arm64, 386, amd64
gomobile bind -v -androidapi 21 -ldflags="-s -w" -o "$OUT_DIR/luminet.aar" -target=android "$TARGET_PKG"
echo "Android AAR compiled successfully: $OUT_DIR/luminet.aar"

# iOS Build (Conditional check to run only on macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Building iOS Framework..."
    gomobile bind -v -ldflags="-s -w" -o "$OUT_DIR/LumiNet.xcframework" -target=ios "$TARGET_PKG"
    echo "iOS Framework compiled successfully: $OUT_DIR/LumiNet.xcframework"
else
    echo "Skipping iOS build (not running on macOS)."
fi

echo "Mobile compilation batch completed successfully!"
