//go:build linux

package proxy

import (
	"syscall"
)

func applySocketMark(fd uintptr, fwmark int) {
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, fwmark)
}
