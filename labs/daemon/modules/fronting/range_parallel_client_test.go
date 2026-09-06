package fronting

import (
	"bytes"
	"testing"
)

func TestComputeChunks(t *testing.T) {
	total := uint64(700000)
	chunkSz := uint64(256 * 1024)
	chunks, err := ComputeChunks(total, chunkSz)
	if err != nil {
		t.Fatalf("ComputeChunks failed: %v", err)
	}

	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}

	if chunks[0].StartByte != 0 || chunks[0].EndByte != 262143 || chunks[0].Length() != 262144 {
		t.Errorf("unexpected chunk 0 bounds")
	}
	if chunks[0].ToRangeHeader() != "bytes=0-262143" {
		t.Errorf("unexpected chunk 0 header: %s", chunks[0].ToRangeHeader())
	}

	if chunks[1].StartByte != 262144 || chunks[1].EndByte != 524287 {
		t.Errorf("unexpected chunk 1 bounds")
	}

	if chunks[2].StartByte != 524288 || chunks[2].EndByte != 699999 || chunks[2].Length() != 175712 {
		t.Errorf("unexpected chunk 2 bounds")
	}
}

func TestParseContentRange(t *testing.T) {
	start, end, total, err := ParseContentRange("bytes 0-262143/1048576")
	if err != nil {
		t.Fatalf("ParseContentRange failed: %v", err)
	}
	if start != 0 || end != 262143 || total != 1048576 {
		t.Errorf("unexpected values: %d, %d, %d", start, end, total)
	}

	// Boundary error start > end
	if _, _, _, err := ParseContentRange("bytes 200-100/500"); err == nil {
		t.Errorf("expected error for start > end")
	}

	// Boundary error end >= total
	if _, _, _, err := ParseContentRange("bytes 0-500/500"); err == nil {
		t.Errorf("expected error for end >= total")
	}
}

func TestRangeParallelStitcher(t *testing.T) {
	total := uint64(30)
	stitcher, err := NewRangeParallelStitcher(total)
	if err != nil {
		t.Fatalf("NewRangeParallelStitcher failed: %v", err)
	}

	chunk0 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	chunk1 := []byte{11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	chunk2 := []byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30}

	// Ingest out-of-order chunk 1 first
	if err := stitcher.IngestChunk(10, chunk1); err != nil {
		t.Fatalf("IngestChunk 1 failed: %v", err)
	}
	if len(stitcher.DrainContiguous()) != 0 {
		t.Errorf("expected no bytes drained when chunk 0 is missing")
	}
	if stitcher.IsComplete() {
		t.Errorf("stitcher should not be complete")
	}

	// Ingest chunk 2
	if err := stitcher.IngestChunk(20, chunk2); err != nil {
		t.Fatalf("IngestChunk 2 failed: %v", err)
	}

	// Ingest chunk 0
	if err := stitcher.IngestChunk(0, chunk0); err != nil {
		t.Fatalf("IngestChunk 0 failed: %v", err)
	}

	drained := stitcher.DrainContiguous()
	if len(drained) != 30 {
		t.Fatalf("expected 30 bytes drained, got %d", len(drained))
	}

	expected := make([]byte, 30)
	for i := 0; i < 30; i++ {
		expected[i] = byte(i + 1)
	}

	if !bytes.Equal(drained, expected) {
		t.Errorf("drained data mismatch")
	}
	if !stitcher.IsComplete() {
		t.Errorf("stitcher should be complete")
	}
}
