//go:build !windows || !cgo

package cmd

import (
	"context"
	"fmt"
)

// runGUI prints a fallback message for CGO-disabled builds and cancels the context.
func runGUI(url, apiKey string, cancel context.CancelFunc) {
	_ = url
	_ = apiKey
	fmt.Println("Native GUI window is not supported in CGO-disabled builds.")
	cancel()
}

func nativeGUIAvailable() bool {
	return false
}
