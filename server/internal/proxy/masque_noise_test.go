package proxy

import (
	"net"
	"testing"
	"time"
)

type mockPacketConn struct {
	net.PacketConn
	sentPackets [][]byte
	remoteAddr  net.Addr
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	payload := make([]byte, len(b))
	copy(payload, b)
	m.sentPackets = append(m.sentPackets, payload)
	m.remoteAddr = addr
	return len(b), nil
}

func (m *mockPacketConn) Close() error {
	return nil
}

func TestMasqueObfuscationPreflight(t *testing.T) {
	mockConn := &mockPacketConn{sentPackets: make([][]byte, 0)}
	config := &NoizeConfig{
		I1:           "<b 01020304><r 8>",
		JcBeforeHS:   2,
		Jmin:         16,
		Jmax:         32,
		JunkInterval: 1 * time.Millisecond,
	}

	noizeConn := NewNoizeUDPConn(mockConn, config)

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:443")
	testPacket := []byte("standard client hello")

	_, err := noizeConn.WriteTo(testPacket, addr)
	if err != nil {
		t.Fatalf("failed to write to noize connection: %v", err)
	}

	// We expect:
	// - 2 junk packets (JcBeforeHS)
	// - 1 signature packet (I1)
	// - 1 standard payload packet (which might be padded/wrapped)
	// Total packets sent: 4
	expectedCount := 4
	if len(mockConn.sentPackets) != expectedCount {
		t.Errorf("expected %d packets sent, got %d", expectedCount, len(mockConn.sentPackets))
	}

	// First two should be junk
	if len(mockConn.sentPackets[0]) < 16 || len(mockConn.sentPackets[0]) > 32 {
		t.Errorf("invalid junk packet size: %d", len(mockConn.sentPackets[0]))
	}

	// Third packet should be our I1 signature (12 bytes: 4 bytes static + 8 bytes random)
	if len(mockConn.sentPackets[2]) != 12 {
		t.Errorf("expected I1 signature packet size 12, got %d", len(mockConn.sentPackets[2]))
	}
	if mockConn.sentPackets[2][0] != 0x01 || mockConn.sentPackets[2][1] != 0x02 {
		t.Errorf("invalid I1 signature packet headers: %v", mockConn.sentPackets[2])
	}
}

func TestAtomicNoizeWireGuardObfuscation(t *testing.T) {
	mockConn := &mockPacketConn{sentPackets: make([][]byte, 0)}
	config := &NoizeConfig{
		I1:           "<b 01020304>",
		JcBeforeHS:   1,
		Jmin:         8,
		Jmax:         16,
		JunkInterval: 1 * time.Millisecond,
	}

	wgConn := NewAtomicNoizeWireGuardConn(mockConn, config)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:2408")

	// WireGuard handshake initiation packet: starts with byte 0x01 and size >= 148
	handshakePacket := make([]byte, 148)
	handshakePacket[0] = 1

	_, err := wgConn.WriteTo(handshakePacket, addr)
	if err != nil {
		t.Fatalf("failed to write to WireGuard obfuscator: %v", err)
	}

	// We expect:
	// - 1 IKEv2-wrapped signature (52 bytes overhead + 4 bytes I1 = 56 bytes)
	// - 1 junk packet (8-16 bytes)
	// - 1 handshake packet (148 bytes)
	// Total packets: 3
	expectedCount := 3
	if len(mockConn.sentPackets) != expectedCount {
		t.Errorf("expected %d packets, got %d", expectedCount, len(mockConn.sentPackets))
	}

	if len(mockConn.sentPackets[0]) != 56 {
		t.Errorf("expected IKEv2-wrapped signature size 56, got %d", len(mockConn.sentPackets[0]))
	}

	// Check IKEv2 Next Payload header matching exchange types
	if mockConn.sentPackets[0][16] != 0x21 { // Next Payload: SA
		t.Errorf("expected IKEv2 Next Payload 0x21, got 0x%x", mockConn.sentPackets[0][16])
	}
}

func TestDetectQUICInitial(t *testing.T) {
	// Simulated QUIC Initial long header packet
	initialPacket := []byte{0x80, 0x00, 0x00, 0x00, 0x01} // Long header (0x80) & Initial type (bits 4-5 are 0)
	if !detectQUICInitial(initialPacket) {
		t.Error("failed to detect valid QUIC Initial packet")
	}

	// Non-Initial packet
	nonInitialPacket := []byte{0x01, 0x02}
	if detectQUICInitial(nonInitialPacket) {
		t.Error("incorrectly flagged non-Initial packet as Initial")
	}
}

func TestDefaultNoizeConfig(t *testing.T) {
	cfg := DefaultNoizeConfig()
	if cfg.MimicProtocol != "stun" {
		t.Errorf("expected default mimic protocol stun, got %s", cfg.MimicProtocol)
	}
}
