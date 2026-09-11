package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/protocols/tlsfragment"
)

func TestAdaptiveDialer_Success(t *testing.T) {
	// Start a local TCP listener to mock the proxy
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err == nil {
			// Read anything or just close
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			conn.Close()
		}
	}()

	addr := l.Addr().(*net.TCPAddr)
	dialer := &AdaptiveDialer{
		ProxyHost: addr.IP.String(),
		ProxyPort: uint16(addr.Port),
		UTLSConfig: tlsfragment.UTLSFragmentConfig{
			Strategy: tlsfragment.StrategySniSplit,
		},
		Timeout: 2 * time.Second,
	}

	conn, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Try writing to trigger the fragmented write logic
	_, err = conn.Write([]byte("dummy TLS client hello prefix and SNI contents"))
	if err != nil {
		t.Errorf("failed to write to connection: %v", err)
	}
}

func TestAdaptiveDialer_EscalationFailsClosedWithoutRawBypass(t *testing.T) {
	// Force the ordinary TCP stage to fail. Raw bypass is a platform/capability
	// dependent feature; when it cannot be installed, Dial must surface that
	// failure rather than fabricate a usable connection.
	dialer := &AdaptiveDialer{
		ProxyHost: "127.0.0.1",
		ProxyPort: 1,
		UTLSConfig: tlsfragment.UTLSFragmentConfig{
			Strategy: tlsfragment.StrategyNone,
		},
		Timeout: 500 * time.Millisecond,
	}

	conn, err := dialer.Dial(context.Background())
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected adaptive dial to fail closed when no usable raw-bypass path is available")
	}
	if conn != nil {
		_ = conn.Close()
		t.Fatal("failed adaptive dial returned a non-nil connection")
	}
}
