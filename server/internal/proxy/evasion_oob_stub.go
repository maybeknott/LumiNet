//go:build !windows && !unix

package proxy

import (
	"net"
)

// sendWithOOB sends data to the connection, falling back to a normal write when raw sockets are unsupported.
func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	toSend := make([]byte, len(data)+1)
	copy(toSend, data)
	toSend[len(data)] = oob
	_, err := conn.Write(toSend)
	return err
}
