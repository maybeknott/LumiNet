package fronting

import (
	"net"
	"testing"
	"time"
)

func TestCdnFrontPoolLifecycle(t *testing.T) {
	pool := NewCdnFrontPool(10*time.Millisecond, 10)
	ip1 := net.ParseIP("192.0.2.1")
	ip2 := net.ParseIP("192.0.2.2")

	err := pool.AddCandidate(ip1, "cdn1.example.com", 443)
	if err != nil {
		t.Fatalf("AddCandidate failed: %v", err)
	}
	err = pool.AddCandidate(ip2, "cdn2.example.com", 443)
	if err != nil {
		t.Fatalf("AddCandidate failed: %v", err)
	}

	best, err := pool.SelectBest()
	if err != nil {
		t.Fatalf("SelectBest failed: %v", err)
	}
	if best == nil {
		t.Fatal("expected non-nil candidate")
	}

	// Record successes
	pool.mu.Lock()
	best.RecordSuccess(20 * time.Millisecond)
	pool.mu.Unlock()

	// Quarantining candidate
	pool.mu.Lock()
	for i := 0; i < 3; i++ {
		best.RecordFailure(50 * time.Millisecond)
	}
	pool.mu.Unlock()

	nextBest, err := pool.SelectBest()
	if err != nil {
		t.Fatalf("SelectBest failed after quarantine: %v", err)
	}
	if nextBest.IP.Equal(best.IP) {
		t.Fatal("quarantined candidate was returned")
	}
}
