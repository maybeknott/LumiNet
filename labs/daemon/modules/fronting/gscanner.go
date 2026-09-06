package fronting

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ProbeResult is the outcome of a single frontend-IP probe.
type ProbeResult struct {
	IP        string `json:"ip"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// OK reports whether the probe completed with an HTTP response.
func (r ProbeResult) OK() bool { return r.Error == "" }

// Scanner probes candidate Google frontend IPs over TLS-with-fronted-SNI,
// mirroring google_ip_scanner.py: HTTPS HEAD request, semaphore-bounded
// concurrency, successful-first latency sort.
type Scanner struct {
	SNI           string
	Concurrency   int
	Timeout       time.Duration
	CandidateIPs  []string
}

// NewScanner builds a scanner with library defaults when slices are empty.
func NewScanner(sni string, ips []string) *Scanner {
	if sni == "" {
		sni = "www.google.com"
	}
	if len(ips) == 0 {
		ips = DefaultCandidateIPs
	}
	return &Scanner{SNI: sni, Concurrency: 8, Timeout: 15 * time.Second, CandidateIPs: ips}
}

// Scan probes every candidate concurrently and returns results sorted with
// successful (lowest-latency first) before failed.
func (s *Scanner) Scan(ctx context.Context) []ProbeResult {
	ips := s.CandidateIPs
	concurrency := s.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]ProbeResult, len(ips))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = s.probe(ctx, addr)
		}(i, ip)
	}
	wg.Wait()
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.OK() != b.OK() {
			return a.OK()
		}
		if a.OK() && b.OK() {
			return a.LatencyMS < b.LatencyMS
		}
		return false
	})
	return results
}

// Reachable counts successful probes.
func Reachable(results []ProbeResult) int {
	count := 0
	for _, r := range results {
		if r.OK() {
			count++
		}
	}
	return count
}

// Fastest returns up to n lowest-latency successful results.
func Fastest(results []ProbeResult, n int) []ProbeResult {
	out := make([]ProbeResult, 0, n)
	for _, r := range results {
		if r.OK() {
			out = append(out, r)
			if len(out) == n {
				break
			}
		}
	}
	return out
}

func (s *Scanner) probe(ctx context.Context, ip string) ProbeResult {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", fmt.Sprintf("%s:443", ip))
	if err != nil {
		return ProbeResult{IP: ip, Error: classifyNetErr(err)}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         s.SNI,
		InsecureSkipVerify: true, // fronting probe: only reachability + HTTP shape matter
		MinVersion:         tls.VersionTLS12,
	})
	handshakeCtx := probeCtx
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		conn.Close()
		return ProbeResult{IP: ip, Error: classifyNetErr(err)}
	}
	request := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", s.SNI)
	if _, err := tlsConn.Write([]byte(request)); err != nil {
		conn.Close()
		return ProbeResult{IP: ip, Error: classifyNetErr(err)}
	}
	buf := make([]byte, 256)
	n, err := tlsConn.Read(buf)
	conn.Close()
	if err != nil && n == 0 {
		return ProbeResult{IP: ip, Error: classifyNetErr(err)}
	}
	response := string(buf[:n])
	if response == "" {
		return ProbeResult{IP: ip, Error: "empty response"}
	}
	if len(response) < 5 || response[:5] != "HTTP/" {
		return ProbeResult{IP: ip, Error: "invalid response"}
	}
	return ProbeResult{IP: ip, LatencyMS: time.Since(start).Milliseconds()}
}

func classifyNetErr(err error) string {
	msg := err.Error()
	switch {
	case containsAny(msg, "timeout", "deadline"):
		return "timeout"
	case containsAny(msg, "refused"):
		return "connection refused"
	case containsAny(msg, "reset"):
		return "connection reset"
	default:
		return msg
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if len(needle) > 0 && contains(haystack, needle) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
