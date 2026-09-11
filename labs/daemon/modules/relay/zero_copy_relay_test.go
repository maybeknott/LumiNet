package relay

import (
	"net"
	"strings"
	"testing"
)

func TestZeroCopyRelaySupervisor(t *testing.T) {
	listen := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8443}
	sup := NewZeroCopyRelaySupervisor(listen, ProxyProtoV1)

	t1 := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}
	t2 := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 443}
	sup.AddEndpoint(t1, 10)
	sup.AddEndpoint(t2, 10)

	client := &net.TCPAddr{IP: net.ParseIP("192.168.1.55"), Port: 52000}
	s1, target1, err := sup.OpenSession(client)
	if err != nil {
		t.Fatal(err)
	}
	s2, target2, err := sup.OpenSession(client)
	if err != nil {
		t.Fatal(err)
	}

	if target1.String() == target2.String() {
		t.Fatalf("expected alternating targets, got %v and %v", target1, target2)
	}

	header := string(sup.GenerateProxyHeader(client, target1))
	if !strings.HasPrefix(header, "PROXY TCP4 192.168.1.55") {
		t.Fatalf("unexpected proxy header: %s", header)
	}

	sup.CloseSession(s1, 2048)
	sup.CloseSession(s2, 4096)
}
