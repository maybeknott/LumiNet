package proxy

import (
	"crypto/rand"
	"math/big"
	"net"
	"time"
)

// PsiphonJitterConn wraps a net.Conn and appends random noise/padding
// to the initial packets to prevent pattern matching by DPI devices.
type PsiphonJitterConn struct {
	net.Conn
	packetCounter int
}

// NewPsiphonJitterConn wraps a connection with jitter and padding.
func NewPsiphonJitterConn(c net.Conn) *PsiphonJitterConn {
	return &PsiphonJitterConn{Conn: c}
}

// Write intercepts the first three packet writes and injects random padding with connection delays.
func (c *PsiphonJitterConn) Write(b []byte) (int, error) {
	c.packetCounter++
	if c.packetCounter <= 3 {
		// Generate random padding size between 32 and 96 bytes
		paddingSize := 32 + getRandomInt(64)
		padding := make([]byte, paddingSize)
		_, _ = rand.Read(padding)

		// Write dummy padding data to create noise
		_, _ = c.Conn.Write(padding)

		// Add a slight latency jitter delay between 5 and 20 ms
		jitterDelay := 5 + getRandomInt(15)
		time.Sleep(time.Duration(jitterDelay) * time.Millisecond)
	}
	return c.Conn.Write(b)
}

func getRandomInt(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}
