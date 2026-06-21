//go:build !windows

package proxy

import (
	"fmt"
	"io"
	"net"
	"golang.org/x/sys/unix"
)

func setOOBInline(conn net.Conn) error {
	return nil
}

func readOOB(conn net.Conn) (byte, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("not a TCP connection")
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var oobBuf [1]byte
	var innerErr error
	var n int
	err = rawConn.Read(func(fd uintptr) bool {
		n, _, innerErr = unix.Recvfrom(int(fd), oobBuf[:], unix.MSG_OOB)
		return innerErr != unix.EAGAIN
	})
	if err != nil {
		return 0, err
	}
	if innerErr != nil {
		return 0, innerErr
	}
	if n == 0 {
		return 0, io.EOF
	}
	return oobBuf[0], nil
}
