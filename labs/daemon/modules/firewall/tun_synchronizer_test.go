package firewall

import (
	"testing"
)

func TestTunRouteSynchronizer(t *testing.T) {
	sync := NewTunRouteSynchronizer(1400)
	if !sync.ShouldBypass("192.168.0.1") {
		t.Fatalf("expected 192.168.0.1 to be bypassed")
	}
	if sync.ShouldBypass("1.1.1.1") {
		t.Fatalf("expected 1.1.1.1 not to be bypassed")
	}

	if sync.CalculateClampedMSS(false) != 1360 {
		t.Fatalf("expected 1360, got %d", sync.CalculateClampedMSS(false))
	}
	if sync.CalculateClampedMSS(true) != 1340 {
		t.Fatalf("expected 1340, got %d", sync.CalculateClampedMSS(true))
	}
}
