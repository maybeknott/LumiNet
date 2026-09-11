package fronting

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

const (
	DefaultRangeChunkBytes   uint64 = 256 * 1024       // 256 KiB
	AppsScriptBodyMaxBytes   uint64 = 40 * 1024 * 1024 // 40 MiB
	BufferedStitchMaxBytes   uint64 = 64 * 1024 * 1024 // 64 MiB
	MaxStreamedRangeBytes    uint64 = 16 * 1024 * 1024 * 1024 // 16 GiB
)

// RangeChunkSpec specifies the byte bounds of an individual chunk.
type RangeChunkSpec struct {
	ChunkIndex int
	StartByte  uint64
	EndByte    uint64 // inclusive
	TotalBytes uint64
}

// Length returns chunk size in bytes.
func (c RangeChunkSpec) Length() int {
	return int(c.EndByte - c.StartByte + 1)
}

// ToRangeHeader formats standard HTTP Range header.
func (c RangeChunkSpec) ToRangeHeader() string {
	return fmt.Sprintf("bytes=%d-%d", c.StartByte, c.EndByte)
}

// ComputeChunks calculates non-overlapping chunk boundaries for parallel downloads.
func ComputeChunks(totalBytes, chunkSize uint64) ([]RangeChunkSpec, error) {
	if totalBytes == 0 {
		return nil, errors.New("total bytes cannot be zero")
	}
	if totalBytes > MaxStreamedRangeBytes {
		return nil, fmt.Errorf("total bytes %d exceeds maximum allowed ceiling of %d bytes", totalBytes, MaxStreamedRangeBytes)
	}

	sz := chunkSize
	if sz == 0 {
		sz = DefaultRangeChunkBytes
	}

	var chunks []RangeChunkSpec
	var start uint64 = 0
	index := 0

	for start < totalBytes {
		end := start + sz - 1
		if end >= totalBytes {
			end = totalBytes - 1
		}
		chunks = append(chunks, RangeChunkSpec{
			ChunkIndex: index,
			StartByte:  start,
			EndByte:    end,
			TotalBytes: totalBytes,
		})
		start = end + 1
		index++
	}

	return chunks, nil
}

// ParseContentRange parses an RFC 7233 Content-Range header.
func ParseContentRange(headerVal string) (uint64, uint64, uint64, error) {
	clean := strings.TrimSpace(headerVal)
	if !strings.HasPrefix(strings.ToLower(clean), "bytes ") {
		return 0, 0, 0, errors.New("invalid content-range prefix")
	}

	rest := strings.TrimSpace(clean[len("bytes "):])
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return 0, 0, 0, errors.New("invalid content-range format")
	}

	total, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid total in content-range: %w", err)
	}

	bounds := strings.Split(strings.TrimSpace(parts[0]), "-")
	if len(bounds) != 2 {
		return 0, 0, 0, errors.New("invalid bounds in content-range")
	}

	start, err := strconv.ParseUint(strings.TrimSpace(bounds[0]), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid start in content-range: %w", err)
	}

	end, err := strconv.ParseUint(strings.TrimSpace(bounds[1]), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid end in content-range: %w", err)
	}

	if start > end || end >= total {
		return 0, 0, 0, errors.New("content-range boundary violation")
	}

	return start, end, total, nil
}

// RangeParallelStitcher reassembles parallel out-of-order chunks into contiguous streams.
type RangeParallelStitcher struct {
	mu                sync.Mutex
	totalBytes        uint64
	chunks            map[uint64][]byte
	nextExpectedStart uint64
}

// NewRangeParallelStitcher creates a new in-memory chunk stitcher.
func NewRangeParallelStitcher(totalBytes uint64) (*RangeParallelStitcher, error) {
	if totalBytes == 0 {
		return nil, errors.New("total bytes must be greater than zero")
	}
	if totalBytes > BufferedStitchMaxBytes {
		return nil, fmt.Errorf("total bytes %d exceeds in-memory stitch capacity of %d bytes", totalBytes, BufferedStitchMaxBytes)
	}
	return &RangeParallelStitcher{
		totalBytes: totalBytes,
		chunks:     make(map[uint64][]byte),
	}, nil
}

// IngestChunk records a chunk and stores it for in-order drain.
func (s *RangeParallelStitcher) IngestChunk(start uint64, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lenBytes := uint64(len(data))
	if start+lenBytes > s.totalBytes {
		return fmt.Errorf("chunk range %d..%d exceeds total file length %d", start, start+lenBytes, s.totalBytes)
	}

	if _, exists := s.chunks[start]; !exists {
		buf := make([]byte, len(data))
		copy(buf, data)
		s.chunks[start] = buf
	}

	return nil
}

// DrainContiguous extracts all contiguous in-order bytes available.
func (s *RangeParallelStitcher) DrainContiguous() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []byte
	for {
		data, ok := s.chunks[s.nextExpectedStart]
		if !ok {
			break
		}
		delete(s.chunks, s.nextExpectedStart)
		s.nextExpectedStart += uint64(len(data))
		out = append(out, data...)
	}

	return out
}

// IsComplete returns true when the full byte range has been drained.
func (s *RangeParallelStitcher) IsComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextExpectedStart == s.totalBytes
}
