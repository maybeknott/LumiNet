package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMTProtoChecker_DeepTest(t *testing.T) {
	// Boot mock TCP listener to handle connection
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	localAddr := listener.Addr().(*net.TCPAddr)

	// Mock server loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_ = c.SetDeadline(time.Now().Add(1 * time.Second))
				// Read handshake frame
				_, _ = c.Read(buf)
				// Simulate network RTT by sleeping briefly
				time.Sleep(5 * time.Millisecond)
				// Send dummy 64 bytes back
				resp := make([]byte, 64)
				_, _ = c.Write(resp)
			}(conn)
		}
	}()

	checker := NewMTProtoChecker(500 * time.Millisecond)
	proxy := MTProtoProxy{
		Host:   "127.0.0.1",
		Port:   localAddr.Port,
		Secret: "dd000102030405060708090a0b0c0d0e0f",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rtt, err := checker.DeepTest(ctx, proxy)
	if err != nil {
		t.Fatalf("unexpected error during deep test: %v", err)
	}

	if rtt <= 0 {
		t.Errorf("expected RTT > 0, got %v", rtt)
	}
}
