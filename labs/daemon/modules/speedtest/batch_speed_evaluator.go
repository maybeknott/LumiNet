package speedtest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// SpeedAction represents an evaluation metric action category.
type SpeedAction string

const (
	ActionTcpPing   SpeedAction = "TcpPing"
	ActionRealPing  SpeedAction = "RealPing"
	ActionUdpEcho   SpeedAction = "UdpEcho"
	ActionSpeedtest SpeedAction = "Speedtest"
)

// EvaluatorOptions defines configuration thresholds for batch speed measurement.
type EvaluatorOptions struct {
	Concurrency      int
	ProbeTimeout     time.Duration
	SpeedtestURL     string
	RealPingURL      string
	MaxDownloadBytes int64
}

// DefaultEvaluatorOptions provides robust baseline benchmark parameters.
func DefaultEvaluatorOptions() EvaluatorOptions {
	return EvaluatorOptions{
		Concurrency:      5,
		ProbeTimeout:     3 * time.Second,
		SpeedtestURL:     "https://speed.cloudflare.com/__down?bytes=25000000",
		RealPingURL:      "http://cp.cloudflare.com/generate_204",
		MaxDownloadBytes: 50 * 1024 * 1024,
	}
}

// CandidateResult records individual target benchmark performance.
type CandidateResult struct {
	Target        string      `json:"target"`
	Action        SpeedAction `json:"action"`
	Success       bool        `json:"success"`
	LatencyMillis int64       `json:"latency_millis"`
	DownloadBytes int64       `json:"download_bytes"`
	SpeedMbps     float64     `json:"speed_mbps"`
	Error         string      `json:"error,omitempty"`
}

// BatchSpeedEvaluator manages concurrent latency and throughput probes across proxy nodes.
type BatchSpeedEvaluator struct {
	options    EvaluatorOptions
	httpClient *http.Client
}

// NewBatchSpeedEvaluator initializes a new evaluator instance.
func NewBatchSpeedEvaluator(options EvaluatorOptions) *BatchSpeedEvaluator {
	if options.Concurrency <= 0 {
		options.Concurrency = 5
	}
	if options.ProbeTimeout <= 0 {
		options.ProbeTimeout = 3 * time.Second
	}
	if options.SpeedtestURL == "" {
		options.SpeedtestURL = "https://speed.cloudflare.com/__down?bytes=25000000"
	}
	if options.RealPingURL == "" {
		options.RealPingURL = "http://cp.cloudflare.com/generate_204"
	}
	if options.MaxDownloadBytes <= 0 {
		options.MaxDownloadBytes = 50 * 1024 * 1024
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: options.ProbeTimeout}).DialContext,
		ResponseHeaderTimeout: options.ProbeTimeout,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
	}

	return &BatchSpeedEvaluator{
		options: options,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   options.ProbeTimeout * 2,
		},
	}
}

// EvaluateTcpPing measures direct TCP handshake connection latency.
func (e *BatchSpeedEvaluator) EvaluateTcpPing(ctx context.Context, target string) (int64, error) {
	d := net.Dialer{Timeout: e.options.ProbeTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds(), nil
}

// EvaluateRealPing tests HTTP connection and response status.
func (e *BatchSpeedEvaluator) EvaluateRealPing(ctx context.Context, customURL string) (int64, error) {
	urlToTest := customURL
	if urlToTest == "" {
		urlToTest = e.options.RealPingURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlToTest, nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	latency := time.Since(start).Milliseconds()
	if resp.StatusCode >= 400 {
		return latency, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return latency, nil
}

// EvaluateUdpEcho sends synthetic probe over UDP socket.
func (e *BatchSpeedEvaluator) EvaluateUdpEcho(ctx context.Context, target string) (int64, error) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return 0, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	probe := []byte{0xAA, 0xBB, 0x01, 0x02}
	start := time.Now()
	_ = conn.SetDeadline(time.Now().Add(e.options.ProbeTimeout))

	if _, err := conn.Write(probe); err != nil {
		return 0, err
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("empty udp payload")
	}

	return time.Since(start).Milliseconds(), nil
}

// EvaluateSpeedtest streams payload bytes and calculates throughput in Mbps.
func (e *BatchSpeedEvaluator) EvaluateSpeedtest(ctx context.Context, downloadURL string) (float64, int64, error) {
	urlToTest := downloadURL
	if urlToTest == "" {
		urlToTest = e.options.SpeedtestURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlToTest, nil)
	if err != nil {
		return 0, 0, err
	}

	start := time.Now()
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return 0, 0, fmt.Errorf("speedtest download failed with HTTP %d", resp.StatusCode)
	}

	buf := make([]byte, 32*1024)
	var totalBytes int64

	for {
		select {
		case <-ctx.Done():
			return 0, totalBytes, ctx.Err()
		default:
		}

		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
			if totalBytes >= e.options.MaxDownloadBytes {
				break
			}
		}
		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			return 0, totalBytes, rErr
		}
	}

	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}

	mbps := (float64(totalBytes) * 8.0) / (elapsed * 1000.0 * 1000.0)
	return mbps, totalBytes, nil
}

// EvaluateBatch orchestrates concurrent evaluation across targets with worker pool.
func (e *BatchSpeedEvaluator) EvaluateBatch(ctx context.Context, action SpeedAction, targets []string) []CandidateResult {
	if len(targets) == 0 {
		return nil
	}

	results := make([]CandidateResult, len(targets))
	var wg sync.WaitGroup
	ch := make(chan int, len(targets))
	for i := range targets {
		ch <- i
	}
	close(ch)

	concurrency := e.options.Concurrency
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	var cancelled atomic.Bool

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range ch {
				if cancelled.Load() || ctx.Err() != nil {
					results[idx] = CandidateResult{
						Target:  targets[idx],
						Action:  action,
						Success: false,
						Error:   "cancelled",
					}
					continue
				}

				target := targets[idx]
				res := CandidateResult{
					Target: target,
					Action: action,
				}

				switch action {
				case ActionTcpPing:
					lat, err := e.EvaluateTcpPing(ctx, target)
					if err != nil {
						res.Success = false
						res.Error = err.Error()
					} else {
						res.Success = true
						res.LatencyMillis = lat
					}
				case ActionRealPing:
					lat, err := e.EvaluateRealPing(ctx, target)
					if err != nil {
						res.Success = false
						res.Error = err.Error()
					} else {
						res.Success = true
						res.LatencyMillis = lat
					}
				case ActionUdpEcho:
					lat, err := e.EvaluateUdpEcho(ctx, target)
					if err != nil {
						res.Success = false
						res.Error = err.Error()
					} else {
						res.Success = true
						res.LatencyMillis = lat
					}
				case ActionSpeedtest:
					speed, bytes, err := e.EvaluateSpeedtest(ctx, target)
					if err != nil {
						res.Success = false
						res.Error = err.Error()
						res.DownloadBytes = bytes
					} else {
						res.Success = true
						res.SpeedMbps = speed
						res.DownloadBytes = bytes
					}
				}

				results[idx] = res
			}
		}()
	}

	wg.Wait()
	return results
}
