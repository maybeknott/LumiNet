package relay

import (
	"testing"
)

func TestWeightedEgressRouter(t *testing.T) {
	router := NewWeightedEgressRouter()
	router.AddRoute("r1", "10.0.0.1:443", 3)
	router.AddRoute("r2", "10.0.0.2:443", 1)

	counts := make(map[string]int)
	for i := 0; i < 4; i++ {
		ep, ok := router.NextRoute()
		if !ok {
			t.Fatalf("expected route")
		}
		counts[ep]++
	}

	if counts["10.0.0.1:443"] != 3 || counts["10.0.0.2:443"] != 1 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
}
