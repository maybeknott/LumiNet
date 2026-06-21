package proxy

import (
	"strings"
	"testing"
	"time"
)

func TestDnsTunnelTransport(t *testing.T) {
	transport := NewDnsTunnelTransport("tunnel.example.com", "sess-12345")
	conn := transport.VirtualConnection()
	defer conn.Close()

	testData := []byte("Hello DNS Covert Tunnel!")
	n, err := conn.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write to DNS tunnel: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}

	queries := GenerateSimulatedDnsTraffic(testData, "tunnel.example.com")
	if len(queries) == 0 {
		t.Errorf("Expected generated queries, got empty list")
	}

	for _, q := range queries {
		t.Logf("Simulated query: %s", q)
	}
}

func TestSendChunkOverDns(t *testing.T) {
	chunk := []byte("test-data")
	_, _ = SendChunkOverDns(chunk, "invalid.example.com")
}

func TestARQWindow(t *testing.T) {
	window := NewARQWindow(4)

	// Add 4 frames (should succeed)
	for i := 0; i < 4; i++ {
		frame, err := window.AddPayload([]byte{byte(i)}, "session-1")
		if err != nil {
			t.Fatalf("Failed to add payload: %v", err)
		}
		if frame.Seq != uint32(i) {
			t.Errorf("Expected Seq %d, got %d", i, frame.Seq)
		}
	}

	// Add 5th frame (should fail since window size is 4)
	_, err := window.AddPayload([]byte{0x04}, "session-1")
	if err == nil {
		t.Fatal("Expected error because send window is full, but got nil")
	}

	// Unacked list should have 4 frames
	unacked := window.GetUnackedFrames()
	if len(unacked) != 4 {
		t.Errorf("Expected 4 unacked frames, got %d", len(unacked))
	}

	// Process ACK for Seq 0
	window.ProcessAck(0)

	// Now we should be able to add 1 more frame
	frame, err := window.AddPayload([]byte{0x04}, "session-1")
	if err != nil {
		t.Fatalf("Failed to add payload after slide: %v", err)
	}
	if frame.Seq != 4 {
		t.Errorf("Expected Seq 4, got %d", frame.Seq)
	}
}

func TestMultipathResolver(t *testing.T) {
	resolvers := []string{"127.0.0.1:53", "8.8.8.8:53"}
	mr := NewMultipathResolver(resolvers)

	healthy := mr.GetHealthyResolvers()
	if len(healthy) != 2 {
		t.Errorf("Expected 2 healthy resolvers, got %d", len(healthy))
	}

	// Run health check with small timeout
	mr.RunHealthCheck(10 * time.Millisecond)

	// Should still return list (even if unhealthy, due to fallback)
	healthy = mr.GetHealthyResolvers()
	if len(healthy) == 0 {
		t.Errorf("Expected fallback resolvers, got empty list")
	}
}

func TestEncodeDnsSubdomain(t *testing.T) {
	frame := &ARQFrame{
		Seq:       12,
		SessionID: "sess-abc",
		Payload:   []byte("data"),
	}
	domain := "tunnel.org"
	subdomain := EncodeDnsSubdomain(frame, domain)

	expectedSuffix := ".12.sess-abc.up.tunnel.org"
	if !strings.HasSuffix(subdomain, expectedSuffix) {
		t.Errorf("Expected subdomain to end with %q, got %q", expectedSuffix, subdomain)
	}
}

func TestResolveHostsSecurelyOverride(t *testing.T) {
	mgr := GetEvasionManager()
	if mgr == nil {
		t.Fatal("EvasionManager is nil")
	}

	// Save original hosts override setting
	orig := mgr.GetHostsOverride()
	defer mgr.SetHostsOverride(orig)

	// Enable HostsOverride
	mgr.SetHostsOverride(true)

	// Test exact match
	ips, err := resolveHostsSecurely("x.com", "")
	if err != nil {
		t.Fatalf("Failed to resolve x.com: %v", err)
	}
	if len(ips) != 1 || ips[0] != "104.19.229.21" {
		t.Errorf("Expected 104.19.229.21 for x.com, got %v", ips)
	}

	// Test wildcard match
	ips2, err := resolveHostsSecurely("r4---sn-bg07rn7e.googlevideo.com", "")
	if err != nil {
		t.Fatalf("Failed to resolve wildcard googlevideo: %v", err)
	}
	if len(ips2) != 1 || ips2[0] != "216.239.38.120" {
		t.Errorf("Expected 216.239.38.120 for googlevideo wildcard, got %v", ips2)
	}

	// Disable HostsOverride
	mgr.SetHostsOverride(false)
	// Verify that the override is not returned
	_, err = resolveHostsSecurely("nonexistent-test-domain-xyz.com", "127.0.0.1:53535")
	if err == nil {
		t.Error("Expected error resolving invalid domain with override disabled")
	}
}
