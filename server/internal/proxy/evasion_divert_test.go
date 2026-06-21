package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestPacketInjector_Lifecycle(t *testing.T) {
	injector := NewPacketInjector()

	if injector.IsRunning() {
		t.Fatal("expected packet injector to not be running initially")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := injector.Start(ctx, 10888)
	if err != nil {
		// If running without Administrator privileges or driver is missing, skip the test.
		t.Skipf("Skipping packet injector start: %v", err)
		return
	}

	// Should be running on Windows/Linux (stubs return false)
	// Let's just verify Start is idempotent and doesn't crash
	err = injector.Start(ctx, 10888)
	if err != nil {
		t.Fatalf("idempotent start failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	err = injector.Stop()
	if err != nil {
		t.Fatalf("failed to stop packet injector: %v", err)
	}

	if injector.IsRunning() {
		t.Fatal("expected packet injector to be stopped")
	}
}

func TestMutateIPv4Source(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("8.8.8.8")

	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], 40)
	binary.BigEndian.PutUint16(pkt[4:], 12345)
	pkt[6] = 0x40
	pkt[7] = 0
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[10:], internetChecksum(pkt[:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:], 12345)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	binary.BigEndian.PutUint32(tcp[4:], 1000)
	binary.BigEndian.PutUint32(tcp[8:], 0)
	tcp[12] = 0x50
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:], 65535)

	pseudo := make([]byte, 12+20)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], 20)
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], internetChecksum(pseudo))

	decoyIP := net.ParseIP("10.0.0.1")
	mutated := MutateIPv4Source(pkt, decoyIP)

	mutatedSrc := net.IP(mutated[12:16])
	if !mutatedSrc.Equal(decoyIP) {
		t.Fatalf("expected source IP to be 10.0.0.1, got %v", mutatedSrc)
	}

	ipChecksum := binary.BigEndian.Uint16(mutated[10:12])
	mutated[10] = 0
	mutated[11] = 0
	expectedIPChecksum := internetChecksum(mutated[:20])
	if ipChecksum != expectedIPChecksum {
		t.Errorf("expected IPv4 checksum %04x, got %04x", expectedIPChecksum, ipChecksum)
	}
}

func TestConnSeqRegistryAndHandshakeParser(t *testing.T) {
	// Test sequence number registry
	RegisterConnSeq(12345, 443, 99999)
	seq, found := GetConnSeq(12345, 443)
	if !found || seq != 99999 {
		t.Fatalf("expected to find registered sequence 99999, got %d (found=%v)", seq, found)
	}

	ClearConnSeq(12345, 443)
	_, found = GetConnSeq(12345, 443)
	if found {
		t.Fatal("expected sequence to be cleared and not found")
	}

	// Test handshake parser with a mock raw TCP SYN packet
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // Version: 4, IHL: 5 (20 bytes)
	pkt[9] = 6    // TCP protocol

	// Set IP source and dest for completeness
	copy(pkt[12:16], net.ParseIP("192.168.1.10").To4())
	copy(pkt[16:20], net.ParseIP("8.8.8.8").To4())

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:], 54321) // Src port
	binary.BigEndian.PutUint16(tcp[2:], 443)   // Dst port
	binary.BigEndian.PutUint32(tcp[4:], 88888) // Seq num
	tcp[13] = 0x02                             // Flags: SYN only

	srcPort, dstPort, tcpSeq, isSyn := parseTCPHandshake(pkt)
	if !isSyn {
		t.Fatal("expected packet to be parsed as a SYN packet")
	}
	if srcPort != 54321 || dstPort != 443 || tcpSeq != 88888 {
		t.Fatalf("unexpected parsed values: srcPort=%d, dstPort=%d, seq=%d", srcPort, dstPort, tcpSeq)
	}

	// Test non-SYN TCP packet
	tcp[13] = 0x12 // SYN-ACK
	_, _, _, isSyn = parseTCPHandshake(pkt)
	if isSyn {
		t.Fatal("expected SYN-ACK packet to not be parsed as a SYN packet")
	}
}

func TestCraftTCPPacket(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("8.8.8.8")
	srcPort := uint16(12345)
	dstPort := uint16(443)
	seq := uint32(100)
	ack := uint32(200)
	flags := uint8(0x18) // PSH-ACK
	payload := []byte("hello")

	pkt := CraftTCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, 64)
	if len(pkt) < 45 {
		t.Fatalf("expected packet length to be at least 45, got %d", len(pkt))
	}

	// Verify IPv4 header version
	version := pkt[0] >> 4
	if version != 4 {
		t.Fatalf("expected IPv4 version, got %d", version)
	}

	// Verify TCP flags
	tcpFlags := pkt[33]
	if tcpFlags != flags {
		t.Fatalf("expected TCP flags %d, got %d", flags, tcpFlags)
	}

	// Test IPv6
	srcIP6 := net.ParseIP("2001:db8::1")
	dstIP6 := net.ParseIP("2001:db8::2")
	pkt6 := CraftTCPPacket(srcIP6, dstIP6, srcPort, dstPort, seq, ack, flags, payload, 64)
	if len(pkt6) < 65 {
		t.Fatalf("expected IPv6 packet length to be at least 65, got %d", len(pkt6))
	}

	version6 := pkt6[0] >> 4
	if version6 != 6 {
		t.Fatalf("expected IPv6 version, got %d", version6)
	}
}

func TestRawBypassConn(t *testing.T) {
	conn := &rawBypassConn{
		localIP:    net.ParseIP("127.0.0.1"),
		remoteIP:   net.ParseIP("127.0.0.1"),
		localPort:  12345,
		remotePort: 80,
		seq:        1000,
		ack:        2000,
		readChan:   make(chan []byte, 10),
		closed:     make(chan struct{}),
	}

	// Push a test payload into read channel
	testPayload := []byte("hello from server")
	conn.readChan <- testPayload

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected successful read, got %v", err)
	}
	if string(buf[:n]) != "hello from server" {
		t.Fatalf("expected 'hello from server', got %s", string(buf[:n]))
	}

	// Close connection
	err = conn.Close()
	if err != nil {
		t.Fatalf("expected successful close, got %v", err)
	}
}


