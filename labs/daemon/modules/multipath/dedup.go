package multipath

import (
	"errors"
	"sync"
	"time"
)

var ErrBufferFull = errors.New("dedup buffer capacity reached")

const DefaultGapTimeout = 3 * time.Second

type DedupBuffer struct {
	mu         sync.Mutex
	next       uint64
	pending    map[uint64][]byte
	cap        int
	gapTimeout time.Duration
	gapSince   time.Time
}

func NewDedupBuffer(startSeq uint64, capacity int, gapTimeout time.Duration) *DedupBuffer {
	if capacity <= 0 {
		capacity = 1024
	}
	if gapTimeout <= 0 {
		gapTimeout = DefaultGapTimeout
	}
	return &DedupBuffer{
		next:       startSeq,
		pending:    make(map[uint64][]byte),
		cap:        capacity,
		gapTimeout: gapTimeout,
	}
}

func (b *DedupBuffer) Push(seq uint64, payload []byte) ([][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if seq < b.next {
		return nil, nil // drop duplicate/old sequence
	}
	if _, exists := b.pending[seq]; exists {
		return nil, nil // drop duplicate
	}

	if len(b.pending) >= b.cap {
		if !b.gapSince.IsZero() && time.Since(b.gapSince) >= b.gapTimeout {
			if recovered := b.skipGapLocked(); len(recovered) > 0 {
				b.pending[seq] = payload
				more := b.drainLocked()
				return append(recovered, more...), nil
			}
		}
		return nil, ErrBufferFull
	}

	b.pending[seq] = payload
	ready := b.drainLocked()

	if len(b.pending) > 0 && len(ready) == 0 {
		if b.gapSince.IsZero() {
			b.gapSince = time.Now()
		} else if time.Since(b.gapSince) >= b.gapTimeout {
			skipped := b.skipGapLocked()
			ready = append(ready, skipped...)
		}
	} else if len(b.pending) == 0 {
		b.gapSince = time.Time{}
	}

	return ready, nil
}

func (b *DedupBuffer) Next() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

func (b *DedupBuffer) CheckTimeout() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.gapSince.IsZero() && time.Since(b.gapSince) >= b.gapTimeout {
		return b.skipGapLocked()
	}
	return nil
}

func (b *DedupBuffer) drainLocked() [][]byte {
	var ready [][]byte
	for {
		p, ok := b.pending[b.next]
		if !ok {
			break
		}
		delete(b.pending, b.next)
		ready = append(ready, p)
		b.next++
	}
	if len(ready) > 0 {
		b.gapSince = time.Time{}
	}
	return ready
}

func (b *DedupBuffer) skipGapLocked() [][]byte {
	if len(b.pending) == 0 {
		return nil
	}
	minSeq := ^uint64(0)
	for k := range b.pending {
		if k < minSeq {
			minSeq = k
		}
	}
	if minSeq <= b.next {
		return nil
	}
	b.next = minSeq
	b.gapSince = time.Time{}
	return b.drainLocked()
}
