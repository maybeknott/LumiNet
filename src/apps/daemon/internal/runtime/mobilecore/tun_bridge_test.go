package mobilecore

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDNSMapper(t *testing.T) {
	mapper := NewDNSMapper()

	// Initial fake IP allocation
	ip1 := mapper.GetFakeIP("example.com")
	if !strings.HasPrefix(ip1, "198.18.") {
		t.Fatalf("expected 198.18.x.y address, got %s", ip1)
	}

	// Idempotent lookup
	ip2 := mapper.GetFakeIP("example.com")
	if ip1 != ip2 {
		t.Fatalf("expected stable fake IP, got %s vs %s", ip1, ip2)
	}

	// Reverse lookup
	host, ok := mapper.GetHostname(ip1)
	if !ok || host != "example.com" {
		t.Fatalf("expected example.com, got host=%s, ok=%v", host, ok)
	}

	// Distinct domains receive distinct IPs
	ip3 := mapper.GetFakeIP("api.cloudflare.com")
	if ip3 == ip1 {
		t.Fatalf("different domains must not receive same IP: %s == %s", ip3, ip1)
	}

	if mapper.Count() != 2 {
		t.Fatalf("expected count 2, got %d", mapper.Count())
	}

	// Reset
	mapper.Reset()
	if mapper.Count() != 0 {
		t.Fatalf("expected count 0 after reset, got %d", mapper.Count())
	}
}

func TestDupFd(t *testing.T) {
	// Negative fd must fail
	_, err := DupFd(-1)
	if err == nil {
		t.Fatalf("expected error for negative fd")
	}

	// Descriptor numbers are process-layout dependent. Open a known-valid
	// descriptor rather than assuming an arbitrary number such as 10 is live.
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open test descriptor: %v", err)
	}
	defer file.Close()

	newFd, err := DupFd(int(file.Fd()))
	if err != nil {
		t.Fatalf("unexpected error for valid fd: %v", err)
	}
	if newFd < 0 {
		t.Fatalf("expected valid newFd, got %d", newFd)
	}
}

func TestParseDNSQueryAndBuildResponse(t *testing.T) {
	// Construct a raw DNS query for "test.local"
	// ID (2 bytes) + Flags (2) + QDCOUNT (2) + ANCOUNT (2) + NSCOUNT (2) + ARCOUNT (2)
	query := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// QNAME: 4 "test" 5 "local" 0
		0x04, 't', 'e', 's', 't',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,
		// QTYPE (A = 1) + QCLASS (IN = 1)
		0x00, 0x01, 0x00, 0x01,
	}

	hostname := ParseDNSQuery(query)
	if hostname != "test.local" {
		t.Fatalf("expected test.local, got '%s'", hostname)
	}

	fakeIP := "198.18.0.42"
	resp := BuildDNSResponse(query, fakeIP)
	if resp == nil {
		t.Fatalf("expected non-nil DNS response")
	}

	// Response header checks
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("ID mismatch in response")
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Fatalf("expected QR bit set in response")
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Fatalf("expected ANCOUNT = 1, got %d", ancount)
	}

	// Last 4 bytes should be the IP 198.18.0.42
	tail := resp[len(resp)-4:]
	expectedIP := net.ParseIP(fakeIP).To4()
	for i := 0; i < 4; i++ {
		if tail[i] != expectedIP[i] {
			t.Fatalf("byte %d mismatch in IP: got %d, want %d", i, tail[i], expectedIP[i])
		}
	}
}

func TestFakeDNSProxyTCPConnectRewrite(t *testing.T) {
	// 1. Start a mock upstream SOCKS5 server
	mockUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen mock upstream: %v", err)
	}
	defer mockUpstream.Close()

	upstreamAddr := mockUpstream.Addr().String()
	receivedDomainChan := make(chan string, 1)

	go func() {
		conn, err := mockUpstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read greeting
		greet := make([]byte, 3)
		if _, err := io.ReadFull(conn, greet); err != nil {
			return
		}
		// Reply NO_AUTH
		_, _ = conn.Write([]byte{5, 0})

		// Read request header
		reqHdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, reqHdr); err != nil {
			return
		}

		atyp := reqHdr[3]
		if atyp == 3 {
			// Domain name atyp
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			domBuf := make([]byte, lenBuf[0])
			if _, err := io.ReadFull(conn, domBuf); err != nil {
				return
			}
			portBuf := make([]byte, 2)
			if _, err := io.ReadFull(conn, portBuf); err != nil {
				return
			}
			receivedDomainChan <- string(domBuf)
		} else {
			receivedDomainChan <- "NOT_DOMAIN"
		}

		// Reply success: 5, 0, 0, 1, 127.0.0.1:8080
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0x1F, 0x90})
	}()

	// 2. Setup DNSMapper and map a domain to fake IP
	mapper := NewDNSMapper()
	targetDomain := "secret-domain.org"
	fakeIPStr := mapper.GetFakeIP(targetDomain)
	fakeIP := net.ParseIP(fakeIPStr).To4()

	// 3. Start FakeDNSProxy
	proxy := NewFakeDNSProxy(upstreamAddr, "", "", mapper)
	proxyAddr, err := proxy.Start()
	if err != nil {
		t.Fatalf("failed to start FakeDNSProxy: %v", err)
	}
	defer proxy.Stop()

	// 4. Connect as a client to FakeDNSProxy
	clientConn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial FakeDNSProxy: %v", err)
	}
	defer clientConn.Close()

	// SOCKS5 client greeting
	_, _ = clientConn.Write([]byte{5, 1, 0})
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, greetResp); err != nil {
		t.Fatalf("failed to read greeting response: %v", err)
	}
	if greetResp[0] != 5 || greetResp[1] != 0 {
		t.Fatalf("greeting rejected: %v", greetResp)
	}

	// SOCKS5 CONNECT targeting FakeIP:443 (atyp = 1)
	connectReq := []byte{5, 1, 0, 1}
	connectReq = append(connectReq, fakeIP...)
	connectReq = append(connectReq, 0x01, 0xBB) // port 443

	if _, err := clientConn.Write(connectReq); err != nil {
		t.Fatalf("failed to write connect request: %v", err)
	}

	select {
	case domain := <-receivedDomainChan:
		if domain != targetDomain {
			t.Fatalf("expected upstream to receive rewritten domain '%s', got '%s'", targetDomain, domain)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for upstream to receive rewritten connect request")
	}
}
