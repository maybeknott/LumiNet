package relay

import (
	"sync"
)

type MultipathDedupBuffer struct {
	mu             sync.Mutex
	expectedSeq    uint64
	seenHistory    map[uint64]struct{}
	reorderQueue   map[uint64][]byte
	maxHistorySize int
}

func NewMultipathDedupBuffer(initialSeq uint64, maxHistory int) *MultipathDedupBuffer {
	if maxHistory <= 0 {
		maxHistory = 128
	}
	return &MultipathDedupBuffer{
		expectedSeq:    initialSeq,
		seenHistory:    make(map[uint64]struct{}),
		reorderQueue:   make(map[uint64][]byte),
		maxHistorySize: maxHistory,
	}
}

func (b *MultipathDedupBuffer) Ingest(seq uint64, data []byte) [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Drop duplicate
	if seq < b.expectedSeq {
		return nil
	}
	if _, seen := b.seenHistory[seq]; seen {
		return nil
	}
	if _, exists := b.reorderQueue[seq]; exists {
		return nil
	}

	b.seenHistory[seq] = struct{}{}
	if len(b.seenHistory) > b.maxHistorySize {
		// Prune
		for k := range b.seenHistory {
			if k < b.expectedSeq {
				delete(b.seenHistory, k)
			}
		}
	}

	b.reorderQueue[seq] = data

	var ready [][]byte
	for {
		pkt, ok := b.reorderQueue[b.expectedSeq]
		if !ok {
			break
		}
		ready = append(ready, pkt)
		delete(b.reorderQueue, b.expectedSeq)
		b.expectedSeq++
	}

	return ready
}

func (b *MultipathDedupBuffer) ExpectedSeq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.expectedSeq
}
