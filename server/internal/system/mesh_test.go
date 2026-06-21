package system

import (
	"bytes"
	"testing"
	"time"
)

func TestMeshManager(t *testing.T) {
	mgr := NewMeshManager()
	
	// Test node link before initialization
	_, err := mgr.EstablishLink("abcd1234")
	if err == nil {
		t.Errorf("EstablishLink before StartNode should have returned error")
	}

	// Initialize
	if err := mgr.StartNode("localNode"); err != nil {
		t.Fatalf("StartNode failed: %v", err)
	}

	// Register peer
	peerAddr := GenerateEphemeralAddress()
	mgr.RegisterPeer("remoteNode", peerAddr)

	node, exists := mgr.nodes["remoteNode"]
	if !exists {
		t.Fatalf("remoteNode peer was not registered")
	}
	if node.Address != peerAddr {
		t.Errorf("got registered address %v, want %v", node.Address, peerAddr)
	}

	// Establish link
	link, err := mgr.EstablishLink("abcd1234")
	if err != nil {
		t.Fatalf("EstablishLink failed: %v", err)
	}
	expectedLink := "link://abcd1234"
	if link != expectedLink {
		t.Errorf("got link %q, want %q", link, expectedLink)
	}
}

func TestLXMFSerialization(t *testing.T) {
	sender := GenerateEphemeralAddress()
	recipient := GenerateEphemeralAddress()
	timestamp := time.Now().Truncate(time.Millisecond) // Truncate to millisecond to avoid nanosecond timezone diff issues in roundtrip
	content := []byte("hello reticulum mesh off-grid messaging payload")

	msg := &LXMFMessage{
		Sender:    sender,
		Recipient: recipient,
		Timestamp: timestamp,
		Content:   content,
	}

	serialized, err := SerializeLXMF(msg)
	if err != nil {
		t.Fatalf("SerializeLXMF failed: %v", err)
	}

	deserialized, err := DeserializeLXMF(serialized)
	if err != nil {
		t.Fatalf("DeserializeLXMF failed: %v", err)
	}

	if deserialized.Sender != sender {
		t.Errorf("got Sender %v, want %v", deserialized.Sender, sender)
	}
	if deserialized.Recipient != recipient {
		t.Errorf("got Recipient %v, want %v", deserialized.Recipient, recipient)
	}
	// Time zone might change so compare Unix nanos
	if deserialized.Timestamp.UnixNano() != timestamp.UnixNano() {
		t.Errorf("got Timestamp %v, want %v", deserialized.Timestamp, timestamp)
	}
	if !bytes.Equal(deserialized.Content, content) {
		t.Errorf("got Content %q, want %q", string(deserialized.Content), string(content))
	}
}
