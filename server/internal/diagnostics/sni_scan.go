package diagnostics

import (
	"crypto/tls"
	"net"
	"time"
)

// ProbeSni tests if a given SNI is allowed or blocked by resolving against a target gateway.
func ProbeSni(targetAddr string, sni string) bool {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	
	// Establish a TCP connection to target gateway IP/port
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Wrap TCP connection with TLS client handshake using the target SNI spoof
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})

	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	err = tlsConn.Handshake()
	
	// If handshake succeeds or returns specific TLS errors (rather than connection reset/timeout),
	// the SNI field is bypassed/allowed by the network middlebox.
	return err == nil
}
