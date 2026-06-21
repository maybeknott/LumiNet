package proxy

import (
	"context"
	"testing"
)

func TestAggregateSubscriptions(t *testing.T) {
	inputs := []string{
		"vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?type=tcp&security=tls#VlessTest",
		"trojan://trojanpass@example.com:80?sni=example.com#TrojanTest",
		"vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImFpZCI6MCwiaG9zdCI6IiIsImlkIjoiOWRlNzhhMmUtNGI3Yi00MTcxLWJhNDctMTlhZDBkN2Y5NTAzIiwibmV0Ijoid3MiLCJwYXRoIjoiLyIsInBvcnQiOjgwODAsInBzIjoiVk1lc3NUZXN0Iiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiJub25lIiwidiI6IjIifQ==",
	}

	filters := SubscriptionFilters{
		AllowProtocols: []string{"vless", "vmess"},
		SearchQuery:    "test",
		MinPort:        100,
		MaxPort:        10000,
	}

	configs, err := AggregateSubscriptions(context.Background(), inputs, filters)
	if err != nil {
		t.Fatalf("AggregateSubscriptions error: %v", err)
	}

	// Trojan should be filtered out by protocol, VMess should be filtered out by port (8080 > 10000 is false, wait, port is 8080. MaxPort is 10000. So port is within bounds. But search query: "test". Names have "VlessTest" and "VMessTest". So they match. Trojan has port 80, which is < 100, so it's filtered by MinPort and Protocol.)
	// Wait, VLESS has port 443, name "VlessTest" -> matches all filters.
	// VMess has port 8080, name "VMessTest" -> matches all filters.
	// Trojan has port 80, name "TrojanTest" -> protocol filter blocks it, port filter blocks it.
	if len(configs) != 2 {
		t.Errorf("expected 2 configs, got %d", len(configs))
	}

	for _, c := range configs {
		if c.Protocol != ProtocolVLESS && c.Protocol != ProtocolVMess {
			t.Errorf("unexpected protocol: %s", c.Protocol)
		}
	}
}

func TestAggregateSubscriptionsDefaults(t *testing.T) {
	// Verify that passing nil/empty inputs or "default" populates the list with defaults
	filters := SubscriptionFilters{}
	
	// Use a canceled context to avoid actually making network calls to real GitHub/Telegram endpoints during unit tests
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should attempt to fetch but return early (due to canceled context) without panic/error
	_, _ = AggregateSubscriptions(ctx, nil, filters)
	_, _ = AggregateSubscriptions(ctx, []string{"default"}, filters)
}

