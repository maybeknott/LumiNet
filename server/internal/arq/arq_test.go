package arq

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockSender captures packets transmitted by the ARQ layer
type mockSender struct {
	mu      sync.Mutex
	packets []capturedPacket
}

type capturedPacket struct {
	packetType uint8
	seq        uint16
	payload    []byte
}

func (m *mockSender) SendPacket(packetType uint8, seq uint16, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = append(m.packets, capturedPacket{
		packetType: packetType,
		seq:        seq,
		payload:    append([]byte(nil), payload...),
	})
	return nil
}

func (m *mockSender) getPackets() []capturedPacket {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]capturedPacket, len(m.packets))
	copy(res, m.packets)
	return res
}

func (m *mockSender) clearPackets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = nil
}

type failSender struct{}

func (failSender) SendPacket(packetType uint8, seq uint16, payload []byte) error {
	return errors.New("network unreachable")
}

func TestARQ_BasicWriteRead(t *testing.T) {
	sender := &mockSender{}
	config := Config{
		WindowSize:               10,
		DefaultRTO:               100 * time.Millisecond,
		MaxRTO:                   1 * time.Second,
		MaxRetries:               5,
		EnableControlReliability: false,
	}

	a := NewARQ(sender, nil, config)
	defer a.Close()

	payload := []byte("Hello ARQ")
	err := a.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write payload: %v", err)
	}

	packets := sender.getPackets()
	if len(packets) != 1 {
		t.Fatalf("Expected 1 captured packet, got %d", len(packets))
	}
	pkt := packets[0]
	if pkt.packetType != PACKET_STREAM_DATA {
		t.Errorf("Expected packet type %d, got %d", PACKET_STREAM_DATA, pkt.packetType)
	}
	if pkt.seq != 1 {
		t.Errorf("Expected packet sequence 1, got %d", pkt.seq)
	}
	if !bytes.Equal(pkt.payload, payload) {
		t.Errorf("Payload mismatch: got %s, want %s", pkt.payload, payload)
	}

	// Feed packet to receiver side
	err = a.HandleInboundPacket(PACKET_STREAM_DATA, 1, payload)
	if err != nil {
		t.Fatalf("HandleInboundPacket failed: %v", err)
	}

	// Expect an ACK response
	packets2 := sender.getPackets()
	if len(packets2) != 2 {
		t.Fatalf("Expected 2 captured packets, got %d", len(packets2))
	}
	ackPkt := packets2[1]
	if ackPkt.packetType != PACKET_STREAM_DATA_ACK {
		t.Errorf("Expected ACK packet type %d, got %d", PACKET_STREAM_DATA_ACK, ackPkt.packetType)
	}
	if ackPkt.seq != 1 {
		t.Errorf("Expected ACK seq 1, got %d", ackPkt.seq)
	}

	// Read from receiver
	readBuf := make([]byte, 20)
	n, err := a.Read(readBuf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Expected to read %d bytes, got %d", len(payload), n)
	}
	if !bytes.Equal(readBuf[:n], payload) {
		t.Errorf("Read mismatch: got %s, want %s", readBuf[:n], payload)
	}
}

func TestARQ_OutOfOrderDelivery(t *testing.T) {
	sender := &mockSender{}
	config := Config{
		WindowSize:               10,
		DefaultRTO:               100 * time.Millisecond,
		MaxRTO:                   1 * time.Second,
		MaxRetries:               5,
		EnableControlReliability: false,
	}

	a := NewARQ(sender, nil, config)
	defer a.Close()

	// Deliver packet 2 first
	err := a.HandleInboundPacket(PACKET_STREAM_DATA, 2, []byte("World"))
	if err != nil {
		t.Fatalf("Failed to handle packet 2: %v", err)
	}

	// Read should block or return nothing since we are waiting on seq 1
	var readN int
	var readErr error
	var wg sync.WaitGroup
	wg.Add(1)

	readBuf := make([]byte, 50)
	go func() {
		defer wg.Done()
		readN, readErr = a.Read(readBuf)
	}()

	// Wait briefly to check if it's blocking
	time.Sleep(50 * time.Millisecond)

	// Deliver packet 1
	err = a.HandleInboundPacket(PACKET_STREAM_DATA, 1, []byte("Hello "))
	if err != nil {
		t.Fatalf("Failed to handle packet 1: %v", err)
	}

	wg.Wait()

	if readErr != nil {
		t.Fatalf("Read returned error: %v", readErr)
	}
	expected := []byte("Hello World")
	if readN != len(expected) {
		t.Errorf("Expected read length %d, got %d", len(expected), readN)
	}
	if !bytes.Equal(readBuf[:readN], expected) {
		t.Errorf("Read data mismatch: got %q, want %q", readBuf[:readN], expected)
	}
}

func TestARQ_Retransmission(t *testing.T) {
	sender := &mockSender{}
	config := Config{
		WindowSize:               10,
		DefaultRTO:               50 * time.Millisecond,
		MaxRTO:                   500 * time.Millisecond,
		MaxRetries:               3,
		EnableControlReliability: false,
	}

	a := NewARQ(sender, nil, config)
	defer a.Close()

	err := a.Write([]byte("lost data"))
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Wait for default RTO (50ms) to elapse
	time.Sleep(100 * time.Millisecond)
	a.CheckRetransmissions()

	packets := sender.getPackets()
	// Should have the original transmission + at least one retransmission
	if len(packets) < 2 {
		t.Fatalf("Expected at least 2 transmissions, got %d", len(packets))
	}

	retransmitPkt := packets[1]
	if retransmitPkt.packetType != PACKET_STREAM_DATA {
		t.Errorf("Expected packet type DATA, got %d", retransmitPkt.packetType)
	}
	if retransmitPkt.seq != 1 {
		t.Errorf("Expected seq 1, got %d", retransmitPkt.seq)
	}
}

func TestARQ_AdaptiveRTO(t *testing.T) {
	sender := &mockSender{}
	config := Config{
		WindowSize:               10,
		DefaultRTO:               50 * time.Millisecond,
		MaxRTO:                   500 * time.Millisecond,
		MaxRetries:               3,
		EnableControlReliability: false,
	}

	a := NewARQ(sender, nil, config)
	defer a.Close()

	err := a.Write([]byte("data"))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Verify initial adaptive RTO state is uninitialized
	a.mu.Lock()
	initBefore := a.dataAdaptiveRTO.initialized
	a.mu.Unlock()
	if initBefore {
		t.Fatalf("Adaptive RTO should be uninitialized initially")
	}

	// Simulate receiving ACK
	err = a.HandleInboundPacket(PACKET_STREAM_DATA_ACK, 1, nil)
	if err != nil {
		t.Fatalf("Handle ACK failed: %v", err)
	}

	a.mu.Lock()
	initAfter := a.dataAdaptiveRTO.initialized
	rtoBase := a.dataAdaptiveRTO.currentBase
	a.mu.Unlock()

	if !initAfter {
		t.Errorf("Expected adaptive RTO to be initialized after ACK")
	}
	if rtoBase < config.DefaultRTO || rtoBase > config.MaxRTO {
		t.Errorf("Adaptive RTO base out of bounds: %v", rtoBase)
	}
}

func TestARQ_DuplicatePackets(t *testing.T) {
	sender := &mockSender{}
	config := Config{
		WindowSize:               10,
		DefaultRTO:               100 * time.Millisecond,
		MaxRTO:                   1 * time.Second,
		MaxRetries:               5,
		EnableControlReliability: false,
	}

	a := NewARQ(sender, nil, config)
	defer a.Close()

	// Feed same sequence packet twice
	payload := []byte("Duplicate")
	err := a.HandleInboundPacket(PACKET_STREAM_DATA, 1, payload)
	if err != nil {
		t.Fatalf("First handle failed: %v", err)
	}

	sender.clearPackets()

	err = a.HandleInboundPacket(PACKET_STREAM_DATA, 1, payload)
	if err != nil {
		t.Fatalf("Second handle failed: %v", err)
	}

	// Should still ACK duplicate packet
	packets := sender.getPackets()
	if len(packets) != 1 {
		t.Fatalf("Expected 1 captured packet for duplicate ACK, got %d", len(packets))
	}
	if packets[0].packetType != PACKET_STREAM_DATA_ACK || packets[0].seq != 1 {
		t.Errorf("Unexpected packet sent on duplicate: %+v", packets[0])
	}
}
