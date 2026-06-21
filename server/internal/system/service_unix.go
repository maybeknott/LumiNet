//go:build !windows

package system

import "fmt"

// RegisterWindowsService stub.
func RegisterWindowsService(name, displayName, description, binPath string, args ...string) error {
	return fmt.Errorf("windows service registration is not supported on this platform")
}

// UnregisterWindowsService stub.
func UnregisterWindowsService(name string) error {
	return fmt.Errorf("windows service registration is not supported on this platform")
}
