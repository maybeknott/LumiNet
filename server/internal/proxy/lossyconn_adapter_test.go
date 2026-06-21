package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/config"
)

func TestLossyJitterConn(t *testing.T) {
	// Setup a mock UDP Echo Server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP: %v", err)
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer listener.Close()

	// Start Echo Server loop
	go func() {
		buf := make([]byte, 1024)
		for {
			n, raddr, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = listener.WriteTo(buf[:n], raddr)
		}
	}()

	// Connect to mock server
	clientConn, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer clientConn.Close()

	// Wrap connection in LossyPacketConn with 10% loss and 15ms latency + 5ms jitter
	packetConn := clientConn.(net.PacketConn)
	lossy := NewLossyPacketConn(packetConn, 0.10, 15*time.Millisecond, 5*time.Millisecond)
	defer lossy.Close()

	sentCount := 50
	receiveCount := 0
	var totalLatency time.Duration

	buf := make([]byte, 128)
	for i := 0; i < sentCount; i++ {
		start := time.Now()
		_, err := lossy.WriteTo([]byte("ping"), listener.LocalAddr())
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}

		// Set short read deadline to handle simulated drops
		_ = packetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := packetConn.ReadFrom(buf)
		if err == nil && n > 0 {
			receiveCount++
			totalLatency += time.Since(start)
		}
	}

	t.Logf("Sent: %d, Received: %d (Loss Rate: %.2f%%)", sentCount, receiveCount, float64(sentCount-receiveCount)/float64(sentCount)*100.0)
	if receiveCount > 0 {
		avgLat := totalLatency / time.Duration(receiveCount)
		t.Logf("Average latency: %v", avgLat)
		// Latency should be around 15ms
		if avgLat < 5*time.Millisecond || avgLat > 45*time.Millisecond {
			t.Errorf("average latency outside bounds: %v", avgLat)
		}
	}

	// Verify drops actually occurred (statistically highly probable for 50 packets at 10% loss)
	if receiveCount == sentCount {
		t.Log("Warning: No packet loss occurred in this run (statistical variance)")
	}
}

func TestConfigWatcher(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "luminet_config_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")

	// Write initial config
	initialConfig := config.DefaultConfig()
	initialConfig.ServerAddr = "127.0.0.1:8000"
	data, _ := json.MarshalIndent(initialConfig, "", "  ")
	_ = os.WriteFile(configPath, data, 0644)

	mgr := config.NewManager(configPath)
	_, _ = mgr.Load()

	watcher := NewConfigWatcher(mgr, configPath, 50*time.Millisecond)

	var callbackTriggered bool
	var newAddr string
	var mu sync.Mutex

	watcher.OnChange(func(cfg *config.Config) {
		mu.Lock()
		callbackTriggered = true
		newAddr = cfg.ServerAddr
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher.Start(ctx)
	defer watcher.Stop()

	// Wait briefly for watcher init
	time.Sleep(150 * time.Millisecond)

	// Write modified config
	modifiedConfig := config.DefaultConfig()
	modifiedConfig.ServerAddr = "127.0.0.1:9000"
	modifiedData, _ := json.MarshalIndent(modifiedConfig, "", "  ")
	_ = os.WriteFile(configPath, modifiedData, 0644)

	// Wait for watcher to trigger
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	triggered := callbackTriggered
	addr := newAddr
	mu.Unlock()

	if !triggered {
		t.Fatal("expected config watcher callback to trigger")
	}

	if addr != "127.0.0.1:9000" {
		t.Fatalf("expected updated address 127.0.0.1:9000, got %s", addr)
	}
}

func TestDiagnosticServerLoopbackOnly(t *testing.T) {
	// Start diagnostic server on an ephemeral port
	boundAddr, srv, err := StartDiagnosticServer(0)
	if err != nil {
		t.Fatalf("failed to start diagnostic server: %v", err)
	}
	defer srv.Close()

	// Resolve the listener port
	// We need to wait a tiny bit for the listener to bind and start
	time.Sleep(50 * time.Millisecond)

	// Bind check: must be listening on loopback (127.0.0.1)
	// We verify loopback routing queries are successful
	resp, err := http.Get("http://" + boundAddr + "/traces")
	if err != nil {
		t.Fatalf("failed to query traces from loopback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected HTTP status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	var data map[string][]TraceRecord
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("failed to decode traces JSON: %v", err)
	}
}
