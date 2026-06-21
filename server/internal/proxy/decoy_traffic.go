package proxy

import (
	"context"
	"crypto/rand"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DecoyTrafficManager generates background HTTP noise traffic.
// This simulates normal web browsing habits to bypass ML-based traffic classification.
type DecoyTrafficManager struct {
	Targets          []string
	VolumePerMinute  int // in KB
	mu               sync.Mutex
	isRunning        bool
	cancel           context.CancelFunc
	httpClient       *http.Client
}

// NewDecoyTrafficManager creates a new DecoyTrafficManager.
func NewDecoyTrafficManager(targets []string, volumePerMinute int) *DecoyTrafficManager {
	if len(targets) == 0 {
		targets = []string{"https://www.google.com", "https://www.wikipedia.org"}
	}
	if volumePerMinute <= 0 {
		volumePerMinute = 120 // Default 120KB per minute (2KB/sec avg)
	}
	return &DecoyTrafficManager{
		Targets:         targets,
		VolumePerMinute: volumePerMinute,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Start launches the background decoy loop.
func (m *DecoyTrafficManager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.isRunning {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.isRunning = true

	go m.loop(ctx)
}

// Stop halts the background decoy loop.
func (m *DecoyTrafficManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isRunning {
		return
	}
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.isRunning = false
}

func (m *DecoyTrafficManager) loop(ctx context.Context) {
	// Average interval target in seconds
	// Total volume target: VolumePerMinute (KB) -> VolumePerSecond = VolumePerMinute / 60
	// Average packet size = 15KB.
	// So average interval = 15KB / VolumePerSecond = 15 * 60 / VolumePerMinute.
	avgInterval := float64(15*60) / float64(m.VolumePerMinute)
	if avgInterval < 1.0 {
		avgInterval = 1.0
	}

	for {
		// Calculate next delay using exponential distribution
		delay := m.exponentialDelay(1.0 / avgInterval)

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		// Pick random target
		target := m.pickRandomTarget()

		// Generate random payload size (between 1KB and 30KB)
		sizeKB := 1 + m.randomRange(29)
		payload := m.generateRandomPayload(int(sizeKB * 1024))

		go m.sendDecoy(ctx, target, payload)
	}
}

func (m *DecoyTrafficManager) pickRandomTarget() string {
	idx := m.randomRange(int64(len(m.Targets)))
	return m.Targets[idx]
}

func (m *DecoyTrafficManager) randomRange(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

func (m *DecoyTrafficManager) exponentialDelay(rate float64) time.Duration {
	// Generate random float between 0 and 1
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	u := 0.5
	if err == nil {
		u = float64(n.Int64()) / 1000000.0
	}
	// Avoid log(0)
	if u == 0 {
		u = 0.00001
	}
	seconds := -math.Log(u) / rate
	return time.Duration(seconds * float64(time.Second))
}

func (m *DecoyTrafficManager) generateRandomPayload(size int) string {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return strings.Repeat("a", size) // Simple text payload to avoid crypto overhead
}

func (m *DecoyTrafficManager) sendDecoy(ctx context.Context, target string, payload string) {
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("X-Decoy-Traffic", "true")

	// Set custom decoy cookie or headers to simulate browser
	u, err := url.Parse(target)
	if err == nil {
		req.Header.Set("Host", u.Host)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Drain response body
	_, _ = io.Copy(io.Discard, resp.Body)
}
