//go:build !linux && !android && !windows

package system

import (
	"errors"
	"net"
	"runtime"
)

func sendRaw(_ net.IP, _ []byte) error {
	return errors.New("raw segment injection needs Linux root or Windows+WinDivert; host is " + runtime.GOOS)
}
