package proxy

import (
	"context"
	"io"
	"testing"
)

func TestGDocsTransport_Simulation(t *testing.T) {
	transport := NewGDocsTransport("mock-folder-id", "") // Empty token triggers simulator mode
	if !transport.UseSimulator {
		t.Fatal("expected simulator mode to be active when token is empty")
	}

	ctx := context.Background()
	testPayload := []byte("hello covert world")

	// Test SendChunk in simulation
	err := transport.SendChunk(ctx, "session-123", 0, testPayload)
	if err != nil {
		t.Fatalf("SendChunk failed in simulation: %v", err)
	}

	// Test ReadChunk in simulation (returns io.EOF to mimic stream end)
	data, err := transport.ReadChunk(ctx, "session-123", 0)
	if err != io.EOF {
		t.Fatalf("expected EOF error in simulation mode, got: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil data on EOF, got: %v", data)
	}
}

func TestGDocsTransport_VirtualConnection(t *testing.T) {
	transport := NewGDocsTransport("mock-folder-id", "") // Simulation mode
	conn := transport.VirtualConnection("session-xyz")
	defer conn.Close()

	// Verify Write returns without error in simulator mode
	payload := []byte("covert payload")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("VirtualConnection.Write failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Expected to write %d bytes, got %d", len(payload), n)
	}

	// Verify Read returns EOF / completes in simulator mode
	buf := make([]byte, 100)
	rn, err := conn.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF on VirtualConnection.Read in simulator mode, got: %v", err)
	}
	if rn != 0 {
		t.Errorf("expected 0 bytes read on EOF, got %d", rn)
	}
}

