package relay

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestRelayAclFilter_SourceWhitelist(t *testing.T) {
	filter := NewRelayAclFilter()

	// Allowed Cloudflare edge IPs
	cfIPs := []string{
		"104.16.24.5",
		"172.67.182.11",
		"162.158.5.10",
		"198.41.130.1",
		"2606:4700:3033::6815:1805",
	}

	for _, ipStr := range cfIPs {
		addr := netip.MustParseAddr(ipStr)
		if !filter.IsSourceAllowed(addr) {
			t.Errorf("Expected %s to be allowed in source whitelist", ipStr)
		}
	}

	// Non-allowed arbitrary / private IPs
	blockedIPs := []string{
		"8.8.8.8",
		"185.199.108.153",
		"192.168.1.100",
		"2001:4860:4860::8888",
	}

	for _, ipStr := range blockedIPs {
		addr := netip.MustParseAddr(ipStr)
		if filter.IsSourceAllowed(addr) {
			t.Errorf("Expected %s to be rejected by source whitelist", ipStr)
		}
	}
}

func TestRelayAclFilter_DestinationBlacklist(t *testing.T) {
	filter := NewRelayAclFilter()

	// Blocked destinations
	blocked := []string{
		"127.0.0.1",
		"::1",
		"93.158.213.92",
		"208.83.20.20",
		"185.102.219.163",
	}

	for _, ipStr := range blocked {
		addr := netip.MustParseAddr(ipStr)
		if filter.IsDestinationAllowed(addr) {
			t.Errorf("Expected %s to be blocked by destination blacklist", ipStr)
		}
	}

	// Clean allowed destinations
	allowed := []string{
		"1.1.1.1",
		"142.250.190.46",
		"2606:4700:4700::1111",
	}

	for _, ipStr := range allowed {
		addr := netip.MustParseAddr(ipStr)
		if !filter.IsDestinationAllowed(addr) {
			t.Errorf("Expected %s to be permitted by destination blacklist", ipStr)
		}
	}
}

func TestRelayAclFilter_Evaluate(t *testing.T) {
	filter := NewRelayAclFilter()

	srcOK := netip.MustParseAddr("104.16.20.1")
	srcBad := netip.MustParseAddr("8.8.8.8")
	dstOK := netip.MustParseAddr("1.1.1.1")
	dstBad := netip.MustParseAddr("127.0.0.1")

	if err := filter.Evaluate(srcOK, dstOK); err != nil {
		t.Fatalf("Expected valid connection to pass, got: %v", err)
	}

	if err := filter.Evaluate(srcBad, dstOK); err == nil {
		t.Fatalf("Expected invalid source to fail evaluation")
	}

	if err := filter.Evaluate(srcOK, dstBad); err == nil {
		t.Fatalf("Expected blocked destination to fail evaluation")
	}
}

func TestUdpOverTcpFramingRoundtrip(t *testing.T) {
	sessionID := [6]byte{0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33}
	streamTag := [2]byte{0x55, 0x66}
	payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}

	encoded := EncodeUdpOverTcpFrame(sessionID, streamTag, payload)
	if len(encoded) != 8+len(payload) {
		t.Fatalf("Expected length %d, got %d", 8+len(payload), len(encoded))
	}

	frame, err := DecodeUdpOverTcpFrame(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if frame.SessionID != sessionID {
		t.Fatalf("SessionID mismatch")
	}
	if frame.StreamTag != streamTag {
		t.Fatalf("StreamTag mismatch")
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("Payload mismatch")
	}

	// Response packet
	respPayload := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01}
	respBytes := BuildUdpResponsePacket(streamTag, respPayload)
	if len(respBytes) != 2+len(respPayload) {
		t.Fatalf("Expected response length %d, got %d", 2+len(respPayload), len(respBytes))
	}

	tag, datagram, err := DecodeUdpResponsePacket(respBytes)
	if err != nil {
		t.Fatalf("DecodeResponse failed: %v", err)
	}
	if tag != streamTag {
		t.Fatalf("Tag mismatch in response")
	}
	if !bytes.Equal(datagram, respPayload) {
		t.Fatalf("Datagram mismatch in response")
	}

	// Short buffer
	if _, err := DecodeUdpOverTcpFrame([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("Expected error on truncated buffer")
	}
	if _, _, err := DecodeUdpResponsePacket([]byte{0x01}); err == nil {
		t.Fatalf("Expected error on truncated response buffer")
	}

	key := ChannelKey("1.1.1.1:53", sessionID, streamTag)
	if key != "1.1.1.1:53:aabbcc1122335566" {
		t.Fatalf("Expected channel key '1.1.1.1:53:aabbcc1122335566', got '%s'", key)
	}
}
