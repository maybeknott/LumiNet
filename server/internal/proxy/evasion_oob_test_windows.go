//go:build windows

package proxy

import (
	"fmt"
	"io"
	"net"
	"golang.org/x/sys/windows"
)

func setOOBInline(conn net.Conn) error {
	// SO_OOBINLINE is unsupported or causes WSAEINVAL on modern Windows Vista+ Loopback.
	// We return nil and read out-of-band data out-of-line using readOOB.
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
		var flags uint32 = windows.MSG_OOB
		var qty uint32
		wsabuf := windows.WSABuf{
			Len: 1,
			Buf: &oobBuf[0],
		}
		innerErr = windows.WSARecv(
			windows.Handle(fd),
			&wsabuf,
			1,
			&qty,
			&flags,
			nil,
			nil,
		)
		n = int(qty)
		// We stop polling when it succeeds or returns an error other than WSAEWOULDBLOCK
		return innerErr != windows.WSAEWOULDBLOCK
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
