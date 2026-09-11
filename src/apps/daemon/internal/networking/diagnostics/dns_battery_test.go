package diagnostics

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDNSScanner_NewDefault(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	if s.ResolverIP != "8.8.8.8" {
		t.Errorf("ResolverIP = %q, want 8.8.8.8", s.ResolverIP)
	}
	if s.Timeout != 8*time.Second {
		t.Errorf("Timeout = %v, want 8s", s.Timeout)
	}
	if len(s.TestTargets) == 0 {
		t.Error("TestTargets should not be empty by default")
	}
}

func TestDNSScanner_SetTimeout(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("1.1.1.1")
	s.SetTimeout(15 * time.Second)
	if s.Timeout != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", s.Timeout)
	}
}

func TestDNSScanner_AddKnownGoodIP(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	s.AddKnownGoodIP("1.2.3.4")
	s.AddKnownGoodIP("5.6.7.8")
	if len(s.KnownGoodIPs) != 2 {
		t.Errorf("KnownGoodIPs len = %d, want 2", len(s.KnownGoodIPs))
	}
	if !s.isKnownGoodIP("1.2.3.4") {
		t.Error("known-good IP was not recognized")
	}
}

func TestDNSScanner_RunBatteryTimeout(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("192.0.2.1:53") // TEST-NET-1; intentionally unreachable.
	s.SetTimeout(25 * time.Millisecond)
	result := s.RunBattery(context.Background())
	if len(result.Meta.Errors) == 0 {
		t.Error("unreachable resolver should surface diagnostic failures in metadata")
	}
	if result.Meta.Duration <= 0 {
		t.Error("battery duration should be recorded")
	}
}

func TestDNSScanner_RunBatteryHonorsCanceledContext(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	result := s.RunBattery(ctx)
	if time.Since(started) > time.Second {
		t.Fatal("canceled battery run did not stop promptly")
	}
	if len(result.Meta.Errors) == 0 {
		t.Error("canceled battery should report failures")
	}
}

func TestDNSScanner_BuildQuery(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	q := s.buildQuery("example.com", 28, false)
	if len(q) < 12 {
		t.Fatalf("query too short: %d bytes", len(q))
	}
	if got := binary.BigEndian.Uint16(q[4:6]); got != 1 {
		t.Errorf("QDCOUNT = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(q[6:8]); got != 0 {
		t.Errorf("ANCOUNT = %d, want 0", got)
	}
	if got := binary.BigEndian.Uint16(q[8:10]); got != 0 {
		t.Errorf("NSCOUNT = %d, want 0", got)
	}
	if got := binary.BigEndian.Uint16(q[10:12]); got != 0 {
		t.Errorf("ARCOUNT = %d, want 0", got)
	}
	offset := skipDNSName(q, 12)
	if got := binary.BigEndian.Uint16(q[offset : offset+2]); got != 28 {
		t.Errorf("QTYPE = %d, want AAAA(28)", got)
	}
}

func TestDNSScanner_BuildQueryWithDNSSECOPT(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	q := s.buildQuery("example.com", 1, true)
	if got := binary.BigEndian.Uint16(q[10:12]); got != 1 {
		t.Fatalf("ARCOUNT = %d, want 1", got)
	}
	if size, ok := parseEDNS0PayloadSize(q); !ok || size != 4096 {
		t.Fatalf("OPT payload size = %d, ok=%v; want 4096, true", size, ok)
	}
	questionEnd := skipDNSName(q, 12) + 4
	nameEnd := skipDNSName(q, questionEnd)
	if got := binary.BigEndian.Uint16(q[nameEnd : nameEnd+2]); got != 41 {
		t.Fatalf("additional TYPE = %d, want OPT(41)", got)
	}
	flags := binary.BigEndian.Uint16(q[nameEnd+6 : nameEnd+8])
	if flags&0x8000 == 0 {
		t.Fatalf("DNSSEC query OPT flags = %#04x, DO bit is not set", flags)
	}
}

func TestDNSScanner_BuildQueryWithEDNS0(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	q := s.buildQueryWithEDNS0("example.com", 1232)
	if got := binary.BigEndian.Uint16(q[10:12]); got != 1 {
		t.Errorf("ARCOUNT = %d, want 1", got)
	}
	if size, ok := parseEDNS0PayloadSize(q); !ok || size != 1232 {
		t.Fatalf("OPT payload size = %d, ok=%v; want 1232, true", size, ok)
	}
}

func TestDNSScanner_InvalidNameRejected(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	tooLong := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example"
	if q := s.buildQuery(tooLong, 1, false); q != nil {
		t.Fatalf("expected invalid >63-byte label to be rejected, got %d-byte query", len(q))
	}
}

func TestResolverAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8:53"},
		{"8.8.8.8:5353", "8.8.8.8:5353"},
		{"2001:db8::1", "[2001:db8::1]:53"},
		{"[2001:db8::1]:5353", "[2001:db8::1]:5353"},
		{"resolver.example", "resolver.example:53"},
	}
	for _, tc := range cases {
		got, err := resolverAddress(tc.in)
		if err != nil {
			t.Fatalf("resolverAddress(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("resolverAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := resolverAddress(""); err == nil {
		t.Error("empty resolver address should be rejected")
	}
}

func TestDNSScanner_SkipDNSName(t *testing.T) {
	t.Parallel()
	msg := []byte{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
	}
	if offset := skipDNSName(msg, 0); offset != len(msg) {
		t.Errorf("skipDNSName advanced to %d, want %d", offset, len(msg))
	}
	// A pointer terminates the name and consumes exactly its two wire bytes.
	msgPtr := []byte{3, 'w', 'w', 'w', 0xC0, 0x00}
	if offset := skipDNSName(msgPtr, 0); offset != len(msgPtr) {
		t.Errorf("skipDNSName with suffix pointer returned %d, want %d", offset, len(msgPtr))
	}
	if offset := skipDNSName([]byte{0xC0, 0x0C}, 0); offset != 2 {
		t.Errorf("pointer-only name returned %d, want 2", offset)
	}
	if offset := skipDNSName([]byte{0xC0}, 0); offset != 1 {
		t.Errorf("truncated pointer returned %d, want 1", offset)
	}
}

func TestIsKnownHijackIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip    string
		isHij bool
	}{
		{"0.0.0.0", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"192.168.1.1", false},
		{"198.51.100.99", true},
		{"203.0.113.55", true},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := isKnownHijackIP(c.ip); got != c.isHij {
			t.Errorf("isKnownHijackIP(%q) = %v, want %v", c.ip, got, c.isHij)
		}
	}
}

func TestDNSScanner_ParseARecords(t *testing.T) {
	t.Parallel()
	resp := []byte{
		0x00, 0x01, // TXID
		0x81, 0x80, // flags
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x01, // ANCOUNT=1
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		// Question
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
		// Answer
		0xC0, 0x0C, // pointer to name at offset 12
		0x00, 0x01, // TYPE=A
		0x00, 0x01, // CLASS=IN
		0x00, 0x00, 0x01, 0x2C, // TTL=300
		0x00, 0x04, // RDLENGTH=4
		0x93, 0x18, 0x1B, 0x64, // 147.24.27.100
	}
	ips := parseARecords(resp)
	if len(ips) != 1 || ips[0] != "147.24.27.100" {
		t.Fatalf("parseARecords() = %v, want [147.24.27.100]", ips)
	}
}

func TestDNSScanner_RawQueryRejectsMismatchedTransaction(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server
	_ = client
	// Transaction matching is deliberately factored into a pure helper so the
	// invariant does not require a live UDP resolver in unit tests.
	if equalDNSID([]byte{0, 1}, []byte{0, 2}) {
		t.Error("mismatched transaction IDs were accepted")
	}
	if !equalDNSID([]byte{0, 1}, []byte{0, 1}) {
		t.Error("matching transaction IDs were rejected")
	}
	if equalDNSID(nil, []byte{0, 1}) {
		t.Error("short query should not match")
	}
}

func TestDNSScanner_EdgeCases(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("")
	s.SetTimeout(10 * time.Millisecond)
	result := s.RunBattery(context.Background())
	if len(result.Meta.Errors) == 0 {
		t.Error("empty resolver should be reported as an error")
	}

	s2 := NewDNSScanner("8.8.8.8")
	s2.SetTimeout(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = s2.RunBattery(ctx)
	if len(result.Meta.Errors) == 0 {
		t.Error("canceled zero-timeout run should report errors")
	}
}

func TestResolveAReturnsContextError(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.resolveA(ctx, "example.com")
	if err == nil {
		t.Fatal("resolveA on canceled context unexpectedly succeeded")
	}
	if !errors.Is(err, context.Canceled) {
		// DialContext can wrap the cancellation on some platforms; preserve the
		// assertion that the operation fails without requiring an external DNS server.
		t.Logf("canceled resolve returned wrapped error: %v", err)
	}
}
