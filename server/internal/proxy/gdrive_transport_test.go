package proxy

import (
	"io"
	"testing"
)

func TestGDriveMailbox(t *testing.T) {
	mailbox := NewGDriveMailbox("folder-123", "session-abc")
	if !mailbox.UseSimulator {
		t.Fatal("expected simulator mode to be active by default")
	}

	conn := mailbox.VirtualConnection()
	defer conn.Close()

	payload := []byte("GDrive packet chunk payload")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write to GDrive mailbox connection: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(payload), n)
	}

	buf := make([]byte, 100)
	rn, err := conn.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF error on simulator read, got %v", err)
	}
	if rn != 0 {
		t.Errorf("Expected 0 bytes read on mock EOF connection, got %d", rn)
	}
}

func TestZephyrEnvelopeEncodingDecoding(t *testing.T) {
	original := &ZephyrEnvelope{
		SessionID:  "test-session-xyz",
		Seq:        42,
		TargetAddr: "google.com:443",
		Payload:    []byte("hello world payload binary data"),
		Close:      true,
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Failed to encode ZephyrEnvelope: %v", err)
	}

	decoded, err := DecodeZephyrEnvelope(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ZephyrEnvelope: %v", err)
	}

	if decoded.SessionID != original.SessionID {
		t.Errorf("Expected SessionID '%s', got '%s'", original.SessionID, decoded.SessionID)
	}
	if decoded.Seq != original.Seq {
		t.Errorf("Expected Seq %d, got %d", original.Seq, decoded.Seq)
	}
	if decoded.TargetAddr != original.TargetAddr {
		t.Errorf("Expected TargetAddr '%s', got '%s'", original.TargetAddr, decoded.TargetAddr)
	}
	if decoded.Close != original.Close {
		t.Errorf("Expected Close %t, got %t", original.Close, decoded.Close)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Expected Payload '%s', got '%s'", string(original.Payload), string(decoded.Payload))
	}
}

