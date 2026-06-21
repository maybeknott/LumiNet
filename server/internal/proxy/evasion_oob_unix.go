//go:build unix

package proxy

import (
	"fmt"
	"net"
	"golang.org/x/sys/unix"
)

// sendWithOOB sends data to the connection, appending the oob byte and sending it with MSG_OOB.
func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get raw conn failed: %w", err)
	}

	toSend := make([]byte, len(data)+1)
	copy(toSend, data)
	toSend[len(data)] = oob

	var innerErr error
	err = rawConn.Write(func(fd uintptr) (done bool) {
		innerErr = unix.Send(int(fd), toSend, unix.MSG_OOB)
		return innerErr != unix.EAGAIN
	})

	if err != nil {
		return fmt.Errorf("rawConn.Write failed: %w", err)
	}
	if innerErr != nil {
		return fmt.Errorf("unix.Send (MSG_OOB) failed: %w", innerErr)
	}
	return nil
}
