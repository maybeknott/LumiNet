package proxy

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// LossyConn wraps a net.Conn and simulates packet loss, latency, and jitter.
type LossyConn struct {
	net.Conn
	lossRate float64 // [0.0, 1.0]
	latency  time.Duration
	jitter   time.Duration
	closed   bool
	mu       sync.Mutex
}

// NewLossyConn creates a LossyConn instance.
func NewLossyConn(conn net.Conn, lossRate float64, latency, jitter time.Duration) *LossyConn {
	return &LossyConn{
		Conn:     conn,
		lossRate: lossRate,
		latency:  latency,
		jitter:   jitter,
	}
}

func (c *LossyConn) calculateDelay() time.Duration {
	if c.latency == 0 {
		return 0
	}
	if c.jitter == 0 {
		return c.latency
	}

	// Dynamic jitter deviation
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(c.jitter*2)))
	var j int64
	if err == nil {
		j = nBig.Int64() - int64(c.jitter)
	}
	delay := c.latency + time.Duration(j)
	if delay < 0 {
		return 0
	}
	return delay
}

func (c *LossyConn) shouldDrop() bool {
	if c.lossRate <= 0 {
		return false
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err == nil {
		val := float64(nBig.Int64()) / 1000.0
		return val < c.lossRate
	}
	return false
}

// Read intercepts reads to introduce latency or drops.
func (c *LossyConn) Read(b []byte) (int, error) {
	if c.shouldDrop() {
		// Simulate drop by causing a temporary read timeout/error
		time.Sleep(100 * time.Millisecond)
		return 0, fmt.Errorf("packet dropped by lossyconn simulation")
	}

	delay := c.calculateDelay()
	if delay > 0 {
		time.Sleep(delay)
	}
	return c.Conn.Read(b)
}

// Write intercepts writes to introduce latency or drops.
func (c *LossyConn) Write(b []byte) (int, error) {
	if c.shouldDrop() {
		// Packet dropped silently
		return len(b), nil
	}

	delay := c.calculateDelay()
	if delay > 0 {
		time.Sleep(delay)
	}
	return c.Conn.Write(b)
}

// LossyPacketConn wraps a net.PacketConn and simulates packet loss, latency, and jitter.
type LossyPacketConn struct {
	net.PacketConn
	lossRate   float64
	latency    time.Duration
	jitter     time.Duration
	writeQueue chan packetJob
	closed     chan struct{}
	wg         sync.WaitGroup
}

type packetJob struct {
	payload []byte
	addr    net.Addr
	deliver time.Time
}

// NewLossyPacketConn wraps a net.PacketConn to simulate loss/latency conditions.
func NewLossyPacketConn(conn net.PacketConn, lossRate float64, latency, jitter time.Duration) *LossyPacketConn {
	lp := &LossyPacketConn{
		PacketConn: conn,
		lossRate:   lossRate,
		latency:    latency,
		jitter:     jitter,
		writeQueue: make(chan packetJob, 1024),
		closed:     make(chan struct{}),
	}
	lp.wg.Add(1)
	go lp.processWriteQueue()
	return lp
}

func (c *LossyPacketConn) calculateDelay() time.Duration {
	if c.latency == 0 {
		return 0
	}
	if c.jitter == 0 {
		return c.latency
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(c.jitter*2)))
	var j int64
	if err == nil {
		j = nBig.Int64() - int64(c.jitter)
	}
	delay := c.latency + time.Duration(j)
	if delay < 0 {
		return 0
	}
	return delay
}

func (c *LossyPacketConn) shouldDrop() bool {
	if c.lossRate <= 0 {
		return false
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err == nil {
		val := float64(nBig.Int64()) / 1000.0
		return val < c.lossRate
	}
	return false
}

// WriteTo delegates writes with delay simulation.
func (c *LossyPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.shouldDrop() {
		return len(b), nil // drop packet silently
	}

	delay := c.calculateDelay()
	if delay == 0 {
		return c.PacketConn.WriteTo(b, addr)
	}

	buf := make([]byte, len(b))
	copy(buf, b)

	select {
	case c.writeQueue <- packetJob{
		payload: buf,
		addr:    addr,
		deliver: time.Now().Add(delay),
	}:
	case <-c.closed:
		return 0, net.ErrClosed
	}

	return len(b), nil
}

func (c *LossyPacketConn) processWriteQueue() {
	defer c.wg.Done()
	for {
		select {
		case <-c.closed:
			return
		case job := <-c.writeQueue:
			now := time.Now()
			if job.deliver.After(now) {
				time.Sleep(job.deliver.Sub(now))
			}
			_, _ = c.PacketConn.WriteTo(job.payload, job.addr)
		}
	}
}

// Close releases resources.
func (c *LossyPacketConn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}
	err := c.PacketConn.Close()
	c.wg.Wait()
	return err
}

// TraceRecord registers deep packet metadata.
type TraceRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"` // "read" or "write"
	Length    int       `json:"length"`
	Payload   []byte    `json:"payload_preview"`
}

var (
	diagnosticTraces   = make(map[string][]TraceRecord)
	diagnosticTracesMu sync.Mutex
)

// AddDiagnosticTrace adds a trace record for a connection.
func AddDiagnosticTrace(connID string, record TraceRecord) {
	diagnosticTracesMu.Lock()
	defer diagnosticTracesMu.Unlock()

	traces := diagnosticTraces[connID]
	if len(traces) >= 100 {
		traces = traces[1:]
	}
	diagnosticTraces[connID] = append(traces, record)
}

// ClearDiagnosticTraces deletes all stored diagnostic traces.
func ClearDiagnosticTraces() {
	diagnosticTracesMu.Lock()
	defer diagnosticTracesMu.Unlock()
	diagnosticTraces = make(map[string][]TraceRecord)
}

// DiagnosticConn intercepts and traces net.Conn read/write packets.
type DiagnosticConn struct {
	net.Conn
	id string
}

// NewDiagnosticConn creates a connection wrapper for diagnostics.
func NewDiagnosticConn(conn net.Conn) *DiagnosticConn {
	var b [8]byte
	_, _ = rand.Read(b[:])
	id := fmt.Sprintf("conn_%x", b)
	return &DiagnosticConn{
		Conn: conn,
		id:   id,
	}
}

// Read traces read segments.
func (c *DiagnosticConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil && n > 0 {
		limit := n
		if limit > 16 {
			limit = 16
		}
		payload := make([]byte, limit)
		copy(payload, b[:limit])
		AddDiagnosticTrace(c.id, TraceRecord{
			Timestamp: time.Now(),
			Direction: "read",
			Length:    n,
			Payload:   payload,
		})
	}
	return n, err
}

// Write traces write segments.
func (c *DiagnosticConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && n > 0 {
		limit := n
		if limit > 16 {
			limit = 16
		}
		payload := make([]byte, limit)
		copy(payload, b[:limit])
		AddDiagnosticTrace(c.id, TraceRecord{
			Timestamp: time.Now(),
			Direction: "write",
			Length:    n,
			Payload:   payload,
		})
	}
	return n, err
}

// StartDiagnosticServer spins up a diagnostic loopback server for querying traces.
func StartDiagnosticServer(port int) (string, *http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/traces", func(w http.ResponseWriter, r *http.Request) {
		diagnosticTracesMu.Lock()
		data, err := json.Marshal(diagnosticTraces)
		diagnosticTracesMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", nil, err
	}

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	return listener.Addr().String(), server, nil
}
