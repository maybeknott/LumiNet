package proxy

import (
	"fmt"
	"net"
	"testing"
)

func TestMultiWireGuardRouter_SelectEndpoint(t *testing.T) {
	configs := []*ProxyConfig{
		{
			Protocol: ProtocolWireGuard,
			Address:  "127.0.0.1",
			Port:     51820,
			Name:     "Endpoint-1",
		},
		{
			Protocol: ProtocolWireGuard,
			Address:  "127.0.0.1",
			Port:     51821,
			Name:     "Endpoint-2",
		},
	}

	router := NewMultiWireGuardRouter(configs)

	// Round 1
	ep1, err := router.SelectEndpoint()
	if err != nil {
		t.Fatalf("failed to select endpoint: %v", err)
	}
	if ep1.Name != "Endpoint-1" {
		t.Errorf("expected Endpoint-1, got %s", ep1.Name)
	}

	ep2, err := router.SelectEndpoint()
	if err != nil {
		t.Fatalf("failed to select endpoint: %v", err)
	}
	if ep2.Name != "Endpoint-2" {
		t.Errorf("expected Endpoint-2, got %s", ep2.Name)
	}

	// Round 2 (should wrap around to 1)
	ep3, err := router.SelectEndpoint()
	if err != nil {
		t.Fatalf("failed to select endpoint: %v", err)
	}
	if ep3.Name != "Endpoint-1" {
		t.Errorf("expected Endpoint-1 wrap around, got %s", ep3.Name)
	}
}

func TestMultiWireGuardRouter_DialOutbound(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	addr, portStr, _ := net.SplitHostPort(l.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	configs := []*ProxyConfig{
		{
			Protocol: ProtocolWireGuard,
			Address:  addr,
			Port:     port,
			Name:     "Endpoint-Local",
		},
	}

	router := NewMultiWireGuardRouter(configs)
	conn, err := router.DialOutbound("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial outbound: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr().String() != l.Addr().String() {
		t.Errorf("expected remote addr %s, got %s", l.Addr(), conn.RemoteAddr())
	}
}
