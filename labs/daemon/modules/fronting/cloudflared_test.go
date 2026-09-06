package fronting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewCloudflaredTunnel_RejectsBadURL(t *testing.T) {
	_, err := NewCloudflaredTunnel(CloudflaredTunnelConfig{
		TunnelURL: "http://insecure.example.com",
	})
	if err == nil {
		t.Fatal("expected error for non-wss URL, got nil")
	}
	if !strings.Contains(err.Error(), "wss://") {
		t.Fatalf("expected wss:// error, got: %v", err)
	}
}

func TestNewCloudflaredTunnel_AppliesDefaults(t *testing.T) {
	tun, err := NewCloudflaredTunnel(CloudflaredTunnelConfig{
		TunnelURL: "wss://tunnel.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tun.config.ConnectTimeout != 15*time.Second {
		t.Errorf("expected default connect timeout 15s, got %v", tun.config.ConnectTimeout)
	}
	if tun.config.MaxRetryAttempts != 5 {
		t.Errorf("expected default max retry 5, got %d", tun.config.MaxRetryAttempts)
	}
	if tun.Stats().State != "idle" {
		t.Errorf("expected initial state idle, got %q", tun.Stats().State)
	}
}

func TestCloudflaredTunnel_ConnectSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("tunnel-ready"))
	}))
	defer srv.Close()

	wssURL := strings.Replace(srv.URL, "http://", "wss://", 1)

	tun, err := NewCloudflaredTunnel(CloudflaredTunnelConfig{
		TunnelURL:        wssURL,
		ConnectTimeout:   2 * time.Second,
		ReadTimeout:      1 * time.Second,
		MaxRetryAttempts: 1,
		InitialBackoff:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := tun.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session")
	}
	defer session.Close()

	// Write/read roundtrip
	go func() {
		session.Write([]byte("hello"))
	}()
	buf := make([]byte, 16)
	// Read with timeout via session close fallback
	readDone := make(chan struct{})
	go func() {
		session.Read(buf)
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		// expected since the test server doesn't echo
	}
}

func TestCloudflaredTunnel_Stats(t *testing.T) {
	tun, err := NewCloudflaredTunnel(CloudflaredTunnelConfig{
		TunnelURL:        "wss://example.com",
		MaxRetryAttempts: 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tun.Close()

	stats := tun.Stats()
	if stats.ReconnectCount != 0 {
		t.Errorf("expected zero reconnect count, got %d", stats.ReconnectCount)
	}
	if stats.State != "idle" {
		t.Errorf("expected idle state, got %q", stats.State)
	}

	jsonStats, err := tun.JSONStats()
	if err != nil {
		t.Fatalf("JSONStats failed: %v", err)
	}
	if len(jsonStats) == 0 {
		t.Error("expected non-empty JSON stats")
	}
}

func TestCloudflaredTunnel_Close(t *testing.T) {
	tun, err := NewCloudflaredTunnel(CloudflaredTunnelConfig{
		TunnelURL: "wss://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := tun.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Errorf("second close should be idempotent: %v", err)
	}

	ctx := context.Background()
	_, err = tun.Connect(ctx)
	if err == nil {
		t.Error("expected error connecting to closed tunnel")
	}
}

func TestCloudflaredDialer_UnsupportedNetwork(t *testing.T) {
	tun, err := NewCloudflaredTunnel(CloudflaredTunnelConfig{
		TunnelURL: "wss://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tun.Close()

	dialer := NewCloudflaredDialer(tun)
	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "udp", "1.2.3.4:5678")
	if err == nil {
		t.Error("expected error for non-tcp network")
	}
}

func TestDeriveAuthKey_Deterministic(t *testing.T) {
	k1 := deriveAuthKey("wss://example.com", "token123")
	k2 := deriveAuthKey("wss://example.com", "token123")
	if k1 != k2 {
		t.Errorf("expected deterministic key, got %q != %q", k1, k2)
	}
	if !strings.HasPrefix(k1, "cf-") {
		t.Errorf("expected cf- prefix, got %q", k1)
	}
}

func TestCloudflaredTunnel_ConcurrentStats(t *testing.T) {
	tun, err := NewCloudflaredTunnel(CloudflaredTunnelConfig{
		TunnelURL: "wss://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tun.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tun.Stats()
		}()
	}
	wg.Wait()
}
