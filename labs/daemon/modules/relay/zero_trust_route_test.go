package relay

import (
	"net"
	"testing"
)

func TestZeroTrustRouteTable(t *testing.T) {
	table := NewZeroTrustRouteTable()
	res := &ZeroTrustResource{
		ID:                    "res-prod-db",
		Name:                  "Production Database",
		NetworkCIDR:           "10.100.0.0/24",
		MappedIP:              net.ParseIP("100.64.0.10"),
		AllowedPermissionMask: 0x00000003,
	}

	if err := table.RegisterResource(res); err != nil {
		t.Fatalf("RegisterResource failed: %v", err)
	}

	found, ok := table.LookupByIP(net.ParseIP("100.64.0.10"))
	if !ok || found.Name != "Production Database" {
		t.Fatal("lookup by IP failed")
	}

	if !table.EvaluateAccess(net.ParseIP("100.64.0.10"), 0x00000003) {
		t.Fatal("exact permission match should succeed")
	}
	if !table.EvaluateAccess(net.ParseIP("100.64.0.10"), 0x00000007) {
		t.Fatal("superset permission match should succeed")
	}
	if table.EvaluateAccess(net.ParseIP("100.64.0.10"), 0x00000001) {
		t.Fatal("subset permission match should fail")
	}
}
