//go:build windows

package proxy

import "errors"

// ProtectSocketUnixListener is a stub on Windows.
func ProtectSocketUnixListener(socketPath string, protectCallback func(int) error) error {
	return errors.New("ProtectSocketUnixListener is not supported on Windows")
}
