//go:build !windows

package system

import (
	"errors"
	"syscall"
)

func protectViaUnixSocket(socketPath string, fd int) error {
	socket, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	err = syscall.Connect(socket, &syscall.SockaddrUnix{Name: socketPath})
	if err != nil {
		return err
	}

	oob := syscall.UnixRights(fd)
	dummy := []byte{1}
	err = syscall.Sendmsg(socket, dummy, oob, nil, 0)
	if err != nil {
		return err
	}

	n, err := syscall.Read(socket, dummy)
	if err != nil {
		return err
	}
	if n != 1 || dummy[0] != 1 {
		return errors.New("failed to protect fd over unix socket")
	}
	return nil
}
