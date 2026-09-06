package relay

import (
	"testing"
	"time"
)

func TestMultipathGatewayCoordinatorRouting(t *testing.T) {
	coord := NewMultipathGatewayCoordinator()

	coord.RegisterLink(EgressLink{
		ID:       "link-fiber",
		RTT:      10 * time.Millisecond,
		Weight:   5,
		IsActive: true,
	})
	coord.RegisterLink(EgressLink{
		ID:       "link-cellular",
		RTT:      60 * time.Millisecond,
		Weight:   2,
		IsActive: true,
	})

	id1, err := coord.RoutePacket(1400)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	id2, err := coord.RoutePacket(1400)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id1 == id2 {
		t.Errorf("round-robin should rotate links: got %s and %s", id1, id2)
	}

	// Disable cellular link
	_ = coord.SetLinkActive("link-cellular", false)
	id3, _ := coord.RoutePacket(1400)
	if id3 != "link-fiber" {
		t.Errorf("expected link-fiber when cellular is inactive, got %s", id3)
	}
}
