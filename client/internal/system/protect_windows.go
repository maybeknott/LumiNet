//go:build windows

package system

import (
	"errors"
)

func protectViaUnixSocket(socketPath string, fd int) error {
	return errors.New("unix socket file descriptor protection is not supported on windows")
}
