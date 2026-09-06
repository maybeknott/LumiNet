package multipath

import (
	"bytes"
	"testing"
	"time"
)

func TestFrameEncodeDecode(t *testing.T) {
	sid := SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	payload := []byte("destination.example.com:443")

	frame := &Frame{
		Type:    TypeHello,
		Session: sid,
		Seq:     42,
		Payload: payload,
	}

	encoded := frame.Encode()
	if len(encoded) != HeaderSize+len(payload) {
		t.Fatalf("expected length %d, got %d", HeaderSize+len(payload), len(encoded))
	}

	decoded, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeFrame failed: %v", err)
	}
	if decoded.Type != TypeHello || decoded.Seq != 42 || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("decoded mismatch: %+v", decoded)
	}
}

func TestDedupBufferReordering(t *testing.T) {
	buf := NewDedupBuffer(0, 50, time.Second)

	// Arrive: 3, 1, 4, 0, 2
	r, _ := buf.Push(3, []byte("f3"))
	if len(r) != 0 {
		t.Fatalf("expected 0 ready, got %d", len(r))
	}
	buf.Push(1, []byte("f1"))
	buf.Push(4, []byte("f4"))

	// Frame 0 arrives: should deliver 0 and 1
	r0, _ := buf.Push(0, []byte("f0"))
	if len(r0) != 2 || string(r0[0]) != "f0" || string(r0[1]) != "f1" {
		t.Fatalf("expected f0 and f1, got: %s, %s", string(r0[0]), string(r0[1]))
	}

	// Frame 2 arrives: should deliver 2, 3, 4
	r2, _ := buf.Push(2, []byte("f2"))
	if len(r2) != 3 || string(r2[0]) != "f2" || string(r2[1]) != "f3" || string(r2[2]) != "f4" {
		t.Fatalf("expected f2, f3, f4, got %d items", len(r2))
	}
	if buf.Next() != 5 {
		t.Fatalf("expected next 5, got %d", buf.Next())
	}
}
