//go:build linux || android

package system

import (
	"golang.org/x/sys/unix"
	"syscall"
)

func setSocketMark(fd int, mark int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_MARK, mark)
}
