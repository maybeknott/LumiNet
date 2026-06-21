package system

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDNSQueryBuilderAndParser(t *testing.T) {
	domain := "abc.xyz.tunnel.com"
	qid := uint16(0xbeef)
	qtype := uint16(16) // TXT

	query, err := buildDNSQuery(domain, qtype, qid)
	if err != nil {
		t.Fatalf("buildDNSQuery failed: %v", err)
	}

	if len(query) < 12 {
		t.Fatalf("query packet too short")
	}

	// Verify ID and flags
	parsedID := uint16(query[0])<<8 | uint16(query[1])
	if parsedID != qid {
		t.Errorf("expected ID 0x%x, got 0x%x", qid, parsedID)
	}

	// Construct mock DNS response in reply to query
	// Flags: QR=1, AA=1, TC=0, RD=1, RA=0, RCODE=0 (0x8500)
	var resp bytes.Buffer
	resp.Write(query[0:2]) // Same ID
	resp.WriteByte(0x85)   // QR=1, AA=1
	resp.WriteByte(0x00)   // RCODE=0
	resp.Write(query[4:6]) // Same QDCOUNT (1)
	resp.WriteByte(0x00)   // ANCOUNT (1)
	resp.WriteByte(0x01)
	resp.Write(query[8:12]) // NSCOUNT, ARCOUNT

	// Question Section (copy from query)
	questionLen := len(query) - 12
	resp.Write(query[12 : 12+questionLen])

	// Answer Section
	// Name: pointer to Question Name (0xc00c)
	resp.WriteByte(0xc0)
	resp.WriteByte(0x0c)
	// Type: TXT (16)
	resp.WriteByte(0x00)
	resp.WriteByte(0x10)
	// Class: IN (1)
	resp.WriteByte(0x00)
	resp.WriteByte(0x01)
	// TTL: 120 (0x00000078)
	resp.Write([]byte{0x00, 0x00, 0x00, 0x78})

	// RDATA TXT payloads: length-prefixed chunks
	payloadData := []byte("hello dns tunnel payload")
	// For TXT, RDATA starts with 1-byte length prefix
	rdataLen := 1 + len(payloadData)
	resp.WriteByte(byte(rdataLen >> 8))
	resp.WriteByte(byte(rdataLen & 0xff))
	resp.WriteByte(byte(len(payloadData)))
	resp.Write(payloadData)

	parsedID, payloads, err := parseDNSResponse(resp.Bytes())
	if err != nil {
		t.Fatalf("parseDNSResponse failed: %v", err)
	}

	if parsedID != qid {
		t.Errorf("expected parsed ID 0x%x, got 0x%x", qid, parsedID)
	}

	if len(payloads) != 1 {
		t.Fatalf("expected 1 TXT payload, got %d", len(payloads))
	}

	if string(payloads[0]) != string(payloadData) {
		t.Errorf("expected payload %q, got %q", string(payloadData), string(payloads[0]))
	}
}

func TestDNSBalancer(t *testing.T) {
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	b := NewDNSBalancer(resolvers, "lowest_latency")

	r1 := b.SelectResolver()
	if r1 != "8.8.8.8:53" && r1 != "1.1.1.1:53" {
		t.Errorf("unexpected resolver selected: %s", r1)
	}

	// Report failure for 1.1.1.1:53 N times to disable it
	for i := 0; i < 5; i++ {
		b.ReportFailure("1.1.1.1:53")
	}

	// balancer should now prefer 8.8.8.8:53
	for i := 0; i < 10; i++ {
		r := b.SelectResolver()
		if r != "8.8.8.8:53" {
			t.Errorf("expected active resolver 8.8.8.8:53, got %s", r)
		}
	}

	// Report latency success to 8.8.8.8:53
	b.ReportSuccess("8.8.8.8:53", 50*time.Millisecond)

	// Re-enable after cooldown
	b.PeriodicReenable()
}

func TestDNSUDPFallbackListener(t *testing.T) {
	// Listen on ephemeral local UDP port
	l := NewDNSUDPFallbackListener("127.0.0.1:0")
	err := l.Start()
	if err != nil {
		t.Fatalf("failed to start fallback listener: %v", err)
	}
	defer l.Stop()

	// Get selected local address
	addr := l.conn.LocalAddr().String()

	// Send DNS query over UDP
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("failed to connect to listener: %v", err)
	}
	defer conn.Close()

	query, _ := buildDNSQuery("test.com", 1, 0x1234)
	_, err = conn.Write(query)
	if err != nil {
		t.Fatalf("failed to send query: %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if n < 12 {
		t.Fatalf("response too short")
	}

	// Check QR and TC bits
	qrTcSet := buf[2]&0x80 != 0 && buf[2]&0x02 != 0
	if !qrTcSet {
		t.Errorf("expected QR and TC bits to be set, flags byte 2: 0x%x", buf[2])
	}
}

func TestDNSTunnelCapacity(t *testing.T) {
	cap1 := dnsNameCapacity("tunnel.luminet.net")
	if cap1 <= 0 {
		t.Errorf("expected positive capacity, got %d", cap1)
	}

	chunks := chunkString("abcdefghijklmnopqrstuvwxyz", 5)
	if len(chunks) != 6 {
		t.Errorf("expected 6 chunks, got %d", len(chunks))
	}
}

func TestDNSMapper(t *testing.T) {
	m := NewDNSMapper()
	ip1 := m.GetFakeIP("google.com")
	if !strings.HasPrefix(ip1, "198.18.") {
		t.Errorf("expected fake IP prefix 198.18., got %s", ip1)
	}

	ip2 := m.GetFakeIP("google.com")
	if ip1 != ip2 {
		t.Errorf("expected same fake IP for same hostname, got %s and %s", ip1, ip2)
	}

	host, ok := m.GetHostname(ip1)
	if !ok || host != "google.com" {
		t.Errorf("expected google.com, got %s", host)
	}

	resolved := m.ResolveAddr(ip1 + ":443")
	if resolved != "google.com:443" {
		t.Errorf("expected resolved address google.com:443, got %s", resolved)
	}
}

func TestBuildMockDNSResponse(t *testing.T) {
	m := NewDNSMapper()
	query, err := buildDNSQuery("yahoo.com", 1, 0xabcd)
	if err != nil {
		t.Fatalf("failed to build query: %v", err)
	}

	resp, err := m.BuildMockDNSResponse(query)
	if err != nil {
		t.Fatalf("failed to build mock DNS response: %v", err)
	}

	id, payloads, err := parseDNSResponse(resp)
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if id != 0xabcd {
		t.Errorf("expected ID 0xabcd, got 0x%x", id)
	}

	_ = payloads
}

func TestBuildICMPPortUnreachable(t *testing.T) {
	// Construct a dummy IPv4 UDP packet
	udpPacket := make([]byte, 40)
	udpPacket[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(udpPacket[2:4], uint16(40))
	udpPacket[9] = 17 // Protocol: UDP
	copy(udpPacket[12:16], net.IPv4(192, 168, 1, 100).To4())
	copy(udpPacket[16:20], net.IPv4(192, 168, 1, 1).To4())

	// Build port unreachable packet
	icmp, err := BuildICMPPortUnreachable(udpPacket)
	if err != nil {
		t.Fatalf("failed to build ICMP unreachable: %v", err)
	}

	if len(icmp) < 20+8+20+8 {
		t.Errorf("ICMP packet too short: %d bytes", len(icmp))
	}

	// Verify ICMP headers
	if icmp[9] != 1 {
		t.Errorf("expected Protocol 1 (ICMP), got %d", icmp[9])
	}

	icmpOffset := int(icmp[0]&0x0F) * 4
	if icmp[icmpOffset] != 3 {
		t.Errorf("expected ICMP Type 3, got %d", icmp[icmpOffset])
	}
	if icmp[icmpOffset+1] != 3 {
		t.Errorf("expected ICMP Code 3, got %d", icmp[icmpOffset+1])
	}
}

func TestScanResolverForTunnel(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve local address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	go func() {
		buf := make([]byte, 512)
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		if n < 12 {
			return
		}

		resp := make([]byte, 12)
		copy(resp[0:2], buf[0:2])
		binary.BigEndian.PutUint16(resp[2:4], 0x8180)
		binary.BigEndian.PutUint16(resp[4:6], 0x0001)
		binary.BigEndian.PutUint16(resp[6:8], 0x0000)
		binary.BigEndian.PutUint16(resp[8:10], 0x0000)
		binary.BigEndian.PutUint16(resp[10:12], 0x0000)

		resp = append(resp, buf[12:n]...)

		time.Sleep(2 * time.Millisecond)
		_, _ = conn.WriteToUDP(resp, raddr)
	}()

	success, rtt, err := ScanResolverForTunnel(localAddr, "tunnel.com", 1*time.Second)
	if err != nil {
		t.Fatalf("ScanResolverForTunnel error: %v", err)
	}

	if !success {
		t.Errorf("expected scan to succeed")
	}

	if rtt <= 0 {
		t.Errorf("expected positive latency RTT, got %v", rtt)
	}
}

