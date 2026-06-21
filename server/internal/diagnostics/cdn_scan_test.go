package diagnostics

import (
	"testing"
	"time"
)

func TestGenerateCdnIPs(t *testing.T) {
	cidrs := []string{"192.168.1.0/24", "10.0.0.1"}
	ips := GenerateCdnIPs(cidrs, 2)
	// 192.168.1.0/24 is a single /24 block. With sampleRate=2, it samples 2 IPs.
	// 10.0.0.1 is a single IP.
	// Total: 3 IPs.
	if len(ips) != 3 {
		t.Errorf("Expected 3 IPs, got %d: %v", len(ips), ips)
	}

	// Try with sampleRate=0 (Full)
	// A /24 subnet has 254 host IPs (excluding .0 and .255)
	ipsFull := GenerateCdnIPs([]string{"192.168.1.0/24"}, 0)
	if len(ipsFull) != 254 {
		t.Errorf("Expected 254 IPs, got %d", len(ipsFull))
	}
}

func TestScanCdnIPDetailed_FailGracefully(t *testing.T) {
	// 127.0.0.1:443 is typically closed, so it should fail gracefully and report alive = false
	res := ScanCdnIPDetailed("127.0.0.1", "speed.cloudflare.com", 100*time.Millisecond)
	if res.Alive {
		t.Errorf("Expected 127.0.0.1:443 to be dead, but got alive = true")
	}
	if res.Error == "" {
		t.Errorf("Expected connection error, but got empty error string")
	}
}
