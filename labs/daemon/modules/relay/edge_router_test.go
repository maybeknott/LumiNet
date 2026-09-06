package relay

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestEdgeRelayRouter_DirectRoute(t *testing.T) {
	router := NewEdgeRelayRouter(DefaultEdgeRelayConfig())
	target := RouteTarget{
		Network:    "tcp",
		Host:       "example.com",
		Port:       80,
		ResolvedIP: netip.MustParseAddr("93.184.216.34"),
	}

	decision := router.DecideRoute(target, nil)
	if decision.IsRelayChained {
		t.Fatalf("Expected direct route for non-Cloudflare TCP target")
	}
	if decision.TargetHost != "example.com" || decision.TargetPort != 80 {
		t.Fatalf("Target endpoint mismatch: %s:%d", decision.TargetHost, decision.TargetPort)
	}
}

func TestEdgeRelayRouter_CloudflareIPChaining(t *testing.T) {
	router := NewEdgeRelayRouter(DefaultEdgeRelayConfig())
	sid := uint64(1)
	target := RouteTarget{
		Network:    "tcp",
		Host:       "cloudflare.com",
		Port:       443,
		ResolvedIP: netip.MustParseAddr("104.16.132.229"), // in 104.16.0.0/13
	}

	decision := router.DecideRoute(target, &sid)
	if !decision.IsRelayChained {
		t.Fatalf("Expected chained relay route for Cloudflare target IP")
	}
	if decision.RelayHost != "relay2.bepass.org" || decision.RelayPort != 6666 {
		t.Fatalf("Relay endpoint mismatch: %s:%d", decision.RelayHost, decision.RelayPort)
	}
	if decision.DelimiterHeader != "tcp@cloudflare.com$443\r\n" {
		t.Fatalf("Delimiter header mismatch: %s", decision.DelimiterHeader)
	}
}

func TestEdgeRelayRouter_UdpChaining(t *testing.T) {
	router := NewEdgeRelayRouter(DefaultEdgeRelayConfig())
	sid := uint64(2)
	target := RouteTarget{
		Network:    "udp",
		Host:       "8.8.8.8",
		Port:       53,
		ResolvedIP: netip.MustParseAddr("8.8.8.8"),
	}

	decision := router.DecideRoute(target, &sid)
	if !decision.IsRelayChained {
		t.Fatalf("Expected chained relay route for UDP target")
	}
	if decision.RelayHost != "relay3.bepass.org" || decision.RelayPort != 6666 {
		t.Fatalf("Relay endpoint mismatch: %s:%d", decision.RelayHost, decision.RelayPort)
	}
	if decision.DelimiterHeader != "udp@8.8.8.8$53\r\n" {
		t.Fatalf("Delimiter header mismatch: %s", decision.DelimiterHeader)
	}
}

func TestEdgeRelayRouter_SessionHashSelection(t *testing.T) {
	router := NewEdgeRelayRouter(DefaultEdgeRelayConfig())

	s0 := uint64(0)
	s1 := uint64(1)
	s2 := uint64(2)
	s3 := uint64(3)

	h0, _ := router.SelectRelayEndpoint(&s0)
	h1, _ := router.SelectRelayEndpoint(&s1)
	h2, _ := router.SelectRelayEndpoint(&s2)
	h3, _ := router.SelectRelayEndpoint(&s3)
	hNil, _ := router.SelectRelayEndpoint(nil)

	if h0 != "relay1.bepass.org" || h1 != "relay2.bepass.org" || h2 != "relay3.bepass.org" || h3 != "relay1.bepass.org" || hNil != "relay1.bepass.org" {
		t.Fatalf("Session hash roundrobin mismatch: %s, %s, %s, %s, %s", h0, h1, h2, h3, hNil)
	}
}

func TestEdgeRelayRouter_FallbackRoute(t *testing.T) {
	router := NewEdgeRelayRouter(DefaultEdgeRelayConfig())
	sid := uint64(4)
	target := RouteTarget{
		Network: "tcp",
		Host:    "api.service.io",
		Port:    443,
	}

	fallback := router.BuildFallbackRelayRoute(target, &sid)
	if !fallback.IsRelayChained {
		t.Fatalf("Expected fallback to be relay chained")
	}
	if fallback.RelayHost != "relay2.bepass.org" {
		t.Fatalf("Fallback relay host mismatch: %s", fallback.RelayHost)
	}
	if fallback.DelimiterHeader != "tcp@api.service.io$443\r\n" {
		t.Fatalf("Fallback header mismatch: %s", fallback.DelimiterHeader)
	}
}

func TestBuildDohAQuery(t *testing.T) {
	query := BuildDohAQuery("example.com")

	if len(query) < 12 {
		t.Fatalf("Query too short: %d", len(query))
	}
	if query[0] != 0x12 || query[1] != 0x34 {
		t.Fatalf("Transaction ID mismatch")
	}
	if query[2] != 0x01 || query[3] != 0x00 {
		t.Fatalf("Flags mismatch")
	}

	expectedQname := []byte("\x07example\x03com\x00")
	if !bytes.Equal(query[12:12+len(expectedQname)], expectedQname) {
		t.Fatalf("QNAME mismatch: %v", query[12:12+len(expectedQname)])
	}

	tail := query[12+len(expectedQname):]
	expectedTail := []byte{0x00, 0x01, 0x00, 0x01}
	if !bytes.Equal(tail, expectedTail) {
		t.Fatalf("QTYPE/QCLASS mismatch: %v", tail)
	}
}
