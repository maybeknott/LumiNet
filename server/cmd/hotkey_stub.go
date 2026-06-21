//go:build !windows || !cgo

package cmd

import "context"

func startGlobalHotkeyListener(ctx context.Context, onTrigger func()) {
	// No-op stub for non-Windows or non-CGO builds
}
