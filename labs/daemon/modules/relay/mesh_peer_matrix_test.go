package relay

import (
	"testing"
)

func TestMeshPeerRoutingCost(t *testing.T) {
	table := NewMeshPeerTable()

	// Direct A -> C is bad (high loss)
	table.RecordLink("nodeA", "nodeC", 100.0, 0.40, 1) // Cost = 70 + 140 + 15 = 225

	// Indirect A -> B -> C is fast
	table.RecordLink("nodeA", "nodeB", 20.0, 0.0, 1)  // Cost = 14 + 0 + 15 = 29
	table.RecordLink("nodeB", "nodeC", 20.0, 0.0, 1)  // Cost = 14 + 0 + 15 = 29 (Total: 58)

	nextHop, cost, err := table.FindBestRoute("nodeA", "nodeC")
	if err != nil {
		t.Fatalf("FindBestRoute error: %v", err)
	}

	if nextHop != "nodeB" {
		t.Errorf("expected nodeB as nextHop, got %s", nextHop)
	}
	if cost >= 225.0 {
		t.Errorf("cost should be optimized, got %f", cost)
	}
}
