package proxy

import (
	"net"
	"testing"
	"time"
)

func TestMultiplexShaperRateLimiting(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer l.Close()

	payload := make([]byte, 20000) // 20KB payload
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(payload)
	}()

	clientConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	// Wrap in rate limiter set to 10KB/second
	// 20KB should take approximately 1-2 seconds to read
	shaped := NewShapedConn(clientConn, 10000, 0)

	t0 := time.Now()
	buf := make([]byte, 1024)
	total := 0
	for total < len(payload) {
		n, err := shaped.Read(buf)
		if err != nil {
			t.Fatalf("read failed at %d: %v", total, err)
		}
		total += n
	}
	duration := time.Since(t0)

	// Since we set readLimit to 10000 bytes/sec, 20000 bytes must take at least 1 second (1000ms)
	if duration < 1000*time.Millisecond {
		t.Errorf("expected transfer to take at least 1s, got %v", duration)
	}

	// Verify data integrity
	if total != len(payload) {
		t.Errorf("got total %d bytes, want %d", total, len(payload))
	}
}
