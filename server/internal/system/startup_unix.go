//go:build !windows

package system

// IsStartupEnabled is a stub for non-Windows platforms.
func IsStartupEnabled() bool {
	return false
}

// EnableStartup is a stub for non-Windows platforms.
func EnableStartup() error {
	return nil
}

// DisableStartup is a stub for non-Windows platforms.
func DisableStartup() error {
	return nil
}
