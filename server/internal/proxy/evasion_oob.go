package proxy

import (
	"errors"
	"net"
	"syscall"
)

// getRawConn returns the raw connection from a net.Conn if supported.
func getRawConn(conn net.Conn) (syscall.RawConn, error) {
	rawConnProvider, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support raw access")
	}
	return rawConnProvider.SyscallConn()
}
