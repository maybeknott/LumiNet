package proxy

import (
	"encoding/base32"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ARQFrame represents a single reliable transmission frame.
type ARQFrame struct {
	Seq       uint32
	SessionID string
	Payload   []byte
	IsAck     bool
}

// ARQWindow manages a sliding window of unacknowledged frames.
type ARQWindow struct {
	mu         sync.Mutex
	sendWindow map[uint32]*ARQFrame
	nextSeq    uint32
	baseSeq    uint32
	windowSize uint32
}

// NewARQWindow creates a new sliding window instance.
func NewARQWindow(size uint32) *ARQWindow {
	return &ARQWindow{
		sendWindow: make(map[uint32]*ARQFrame),
		windowSize: size,
	}
}

// AddPayload creates a new frame for the payload if window slot is available.
func (w *ARQWindow) AddPayload(data []byte, sessionID string) (*ARQFrame, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.nextSeq-w.baseSeq >= w.windowSize {
		return nil, fmt.Errorf("send window full (nextSeq: %d, baseSeq: %d, size: %d)", w.nextSeq, w.baseSeq, w.windowSize)
	}

	frame := &ARQFrame{
		Seq:       w.nextSeq,
		SessionID: sessionID,
		Payload:   data,
		IsAck:     false,
	}
	w.sendWindow[w.nextSeq] = frame
	w.nextSeq++
	return frame, nil
}

// ProcessAck removes acknowledged frames and slides the window base forward.
func (w *ARQWindow) ProcessAck(seq uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.sendWindow, seq)
	if seq == w.baseSeq {
		for {
			w.baseSeq++
			if _, exists := w.sendWindow[w.baseSeq]; !exists {
				break
			}
		}
	}
}

// GetUnackedFrames returns all frames currently in the send window that need retransmission.
func (w *ARQWindow) GetUnackedFrames() []*ARQFrame {
	w.mu.Lock()
	defer w.mu.Unlock()

	var frames []*ARQFrame
	for _, f := range w.sendWindow {
		frames = append(frames, f)
	}
	return frames
}

// ResolverHealth tracks the operational metrics of a single DNS resolver endpoint.
type ResolverHealth struct {
	Address   string
	Latency   time.Duration
	LastSeen  time.Time
	IsHealthy bool
}

// MultipathResolver distributes queries concurrently across multiple resolver endpoints.
type MultipathResolver struct {
	mu        sync.Mutex
	resolvers []*ResolverHealth
}

// NewMultipathResolver creates a new multipath routing resolver.
func NewMultipathResolver(addresses []string) *MultipathResolver {
	var list []*ResolverHealth
	for _, addr := range addresses {
		list = append(list, &ResolverHealth{
			Address:   addr,
			IsHealthy: true,
		})
	}
	return &MultipathResolver{resolvers: list}
}

// GetHealthyResolvers returns all healthy resolver endpoints.
func (mr *MultipathResolver) GetHealthyResolvers() []string {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	var addresses []string
	for _, r := range mr.resolvers {
		if r.IsHealthy {
			addresses = append(addresses, r.Address)
		}
	}
	// Fallback to all if none are healthy
	if len(addresses) == 0 {
		for _, r := range mr.resolvers {
			addresses = append(addresses, r.Address)
		}
	}
	return addresses
}

// RunHealthCheck updates latency and health status for each resolver.
func (mr *MultipathResolver) RunHealthCheck(timeout time.Duration) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	for _, r := range mr.resolvers {
		start := time.Now()
		conn, err := net.DialTimeout("udp", r.Address, timeout)
		if err != nil {
			r.IsHealthy = false
			continue
		}
		conn.Close()
		r.Latency = time.Since(start)
		r.LastSeen = time.Now()
		r.IsHealthy = true
	}
}

// EncodeDnsSubdomain serializes a frame's fields into a 63-character base32 DNS label.
func EncodeDnsSubdomain(frame *ARQFrame, baseDomain string) string {
	encoded := base32.StdEncoding.EncodeToString(frame.Payload)
	// Remove base32 padding to save space
	encoded = strings.TrimRight(encoded, "=")
	return fmt.Sprintf("%s.%d.%s.up.%s", encoded, frame.Seq, frame.SessionID, baseDomain)
}
