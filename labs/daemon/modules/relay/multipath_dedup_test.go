package relay

import (
	"bytes"
	"testing"
)

func TestMultipathDedupBuffer(t *testing.T) {
	buf := NewMultipathDedupBuffer(1, 64)

	// Out of order: seq 2 arrives first
	r1 := buf.Ingest(2, []byte("pkt2"))
	if len(r1) != 0 {
		t.Fatalf("expected no ready packets yet")
	}

	// Duplicate seq 2 arrives -> dropped
	rDup := buf.Ingest(2, []byte("pkt2-dup"))
	if len(rDup) != 0 {
		t.Fatalf("expected dup to be dropped")
	}

	// Seq 1 arrives -> both 1 and 2 ready!
	r2 := buf.Ingest(1, []byte("pkt1"))
	if len(r2) != 2 {
		t.Fatalf("expected 2 packets ready, got %d", len(r2))
	}
	if !bytes.Equal(r2[0], []byte("pkt1")) || !bytes.Equal(r2[1], []byte("pkt2")) {
		t.Fatalf("packets out of order")
	}

	if buf.ExpectedSeq() != 3 {
		t.Fatalf("expected seq 3, got %d", buf.ExpectedSeq())
	}
}
