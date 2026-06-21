package system

import (
	"runtime"
	"testing"
)

func TestIsRunningInVM(t *testing.T) {
	// Running this test locally will return true/false depending on if the user is in a VM or on bare metal
	// We want to verify that the call completes without crashing on any platform.
	inVM := IsRunningInVM()
	t.Logf("Running inside VM check: %t (OS: %s)", inVM, runtime.GOOS)

	// Verify helpers compile and work
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		_ = isVMLinux()
	} else if runtime.GOOS == "windows" {
		_ = isVMWindows()
	}
}
