//go:build windows

package proxy

import (
	"fmt"
	"net"
	"golang.org/x/sys/windows"
)

// sendWithOOB sends data to the connection, appending the oob byte and sending it with MSG_OOB.
func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get raw conn failed: %w", err)
	}

	var toSend []byte
	if data == nil {
		toSend = []byte{oob}
	} else {
		toSend = make([]byte, len(data)+1)
		copy(toSend, data)
		toSend[len(data)] = oob
	}

	wsabuf := windows.WSABuf{
		Len: uint32(len(toSend)),
		Buf: &toSend[0],
	}

	var n uint32
	var innerErr error
	err = rawConn.Write(func(fd uintptr) (done bool) {
		innerErr = windows.WSASend(
			windows.Handle(fd),
			&wsabuf,
			1,
			&n,
			windows.MSG_OOB,
			nil,
			nil,
		)
		return innerErr != windows.WSAEWOULDBLOCK
	})

	if err != nil {
		return fmt.Errorf("rawConn.Write failed: %w", err)
	}
	if innerErr != nil && innerErr != windows.NOERROR {
		return fmt.Errorf("WSASend (MSG_OOB) failed: %v", innerErr)
	}
	return nil
}
