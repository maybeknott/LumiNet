// Package proxy provides proxy parsing, testing, and core process management.
//
// tester.go implements the proxy testing engine, ported from the Python
// proxy-tester project. It supports concurrent testing, speed tests,
// GeoIP enrichment, and stability analysis.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	netproxy "golang.org/x/net/proxy"
)

// ProxyTester orchestrates concurrent proxy testing with configurable
// parameters for latency, speed, GeoIP, and stability testing.
type ProxyTester struct {
	config      TestConfig
	coreManager *CoreManager
	results     []*TestResult
	mu          sync.Mutex
	cancel      context.CancelFunc
	progress    TestProgress
	paused      bool
	pauseCond   *sync.Cond
	inProgress  bool
}

// TestConfig holds configuration for a proxy testing session.
type TestConfig struct {
	// TestURLs are the URLs used for connectivity and latency testing.
	TestURLs []string
	// Timeout is the per-test timeout in seconds.
	Timeout int
	// Concurrency is the maximum number of simultaneous tests.
	Concurrency int
	// SpeedTestEnabled enables download speed measurement.
	SpeedTestEnabled bool
	// GeoIPEnabled enables GeoIP lookup for working proxies.
	GeoIPEnabled bool
	// StabilityRuns is the number of repeated tests for stability analysis.
	StabilityRuns int
	// AdaptiveConcurrency enables automatic concurrency adjustment based on system load.
	AdaptiveConcurrency bool
	// DnsResolver is an optional custom DNS resolver for hostname pre-checks.
	DnsResolver string
	// SimulatePoorNetwork enables packet loss/latency simulation during testing
	SimulatePoorNetwork bool
	// LossRate is the simulated loss rate [0.0, 1.0]
	LossRate            float64
	// LatencyMs is the mean latency in milliseconds
	LatencyMs           int
	// JitterMs is the jitter deviation in milliseconds
	JitterMs            int
	// DiagnosticsEnabled enables deep packet capture diagnostics
	DiagnosticsEnabled  bool
}

// TestResult holds the outcome of testing a single proxy.
type TestResult struct {
	// Proxy is the original proxy configuration that was tested.
	Proxy *ProxyConfig
	// Latency is the measured latency in milliseconds.
	Latency float64
	// DownloadSpeed is the measured download speed in bytes/sec.
	DownloadSpeed float64
	// Score is a composite quality score (0-100).
	Score float64
	// GeoInfo contains geographic information about the proxy's exit IP.
	GeoInfo *GeoInfo
	// Status is the test outcome: "working", "timeout", "error", etc.
	Status string
	// Error contains error details if the test failed.
	Error string
	// StabilityResults holds latency measurements from stability runs.
	StabilityResults []float64
}

// GeoInfo holds geographic information about an IP address.
// Duplicated here for package-level reference; canonical definition in enrichment package.
type GeoInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	ISP         string  `json:"isp"`
	ASN         string  `json:"asn"`
	Org         string  `json:"org"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// TestProgress tracks the overall progress of a testing session.
type TestProgress struct {
	// Total is the total number of proxies to test.
	Total int
	// Completed is the number of proxies tested so far.
	Completed int
	// Working is the number of proxies that passed testing.
	Working int
	// Failed is the number of proxies that failed testing.
	Failed int
	// ElapsedMs is the elapsed time in milliseconds since testing started.
	ElapsedMs int64
}

// NewProxyTester creates a new ProxyTester with the given configuration and core manager.
func NewProxyTester(config TestConfig, coreMgr *CoreManager) *ProxyTester {
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}
	if config.Timeout <= 0 {
		config.Timeout = 10
	}
	if len(config.TestURLs) == 0 {
		config.TestURLs = []string{"http://cp.cloudflare.com/"}
	}
	if config.StabilityRuns <= 0 {
		config.StabilityRuns = 1
	}
	m := &sync.Mutex{}
	return &ProxyTester{
		config:      config,
		coreManager: coreMgr,
		pauseCond:   sync.NewCond(m),
	}
}

// Start begins testing the provided list of proxies concurrently.
// Results are accumulated and can be retrieved via Results().
// The context controls the overall testing lifecycle.
func (t *ProxyTester) Start(ctx context.Context, proxies []*ProxyConfig) error {
	t.mu.Lock()
	if t.inProgress {
		t.mu.Unlock()
		return fmt.Errorf("testing already in progress")
	}
	t.inProgress = true
	t.results = make([]*TestResult, len(proxies))
	t.progress = TestProgress{
		Total:     len(proxies),
		Completed: 0,
		Working:   0,
		Failed:    0,
		ElapsedMs: 0,
	}
	t.paused = false

	ctx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	t.mu.Unlock()

	startTime := time.Now()

	// Update elapsed time periodically
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				t.mu.Lock()
				t.progress.ElapsedMs = time.Since(startTime).Milliseconds()
				t.mu.Unlock()
			}
		}
	}()

	// Queue of proxy indexes
	queue := make(chan int, len(proxies))
	for i := range proxies {
		queue <- i
	}
	close(queue)

	var wg sync.WaitGroup
	concurrency := t.config.Concurrency

	// To allocate ports dynamically
	var portMutex sync.Mutex
	nextPort := 20000

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range queue {
				// Check cancellation
				if ctx.Err() != nil {
					return
				}

				// Handle pause
				t.pauseCond.L.Lock()
				for t.paused {
					t.pauseCond.Wait()
					if ctx.Err() != nil {
						t.pauseCond.L.Unlock()
						return
					}
				}
				t.pauseCond.L.Unlock()

				// Lease port
				portMutex.Lock()
				socksPort := nextPort
				nextPort++
				portMutex.Unlock()

				// Test the proxy
				p := proxies[idx]
				res := t.testSingleOnPort(ctx, p, socksPort)

				// Save results
				t.mu.Lock()
				t.results[idx] = res
				t.progress.Completed++
				if res.Status == "working" {
					t.progress.Working++
				} else {
					t.progress.Failed++
				}
				t.mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Clear temporary diagnostic traces on test completion to prevent storage fill-ups
	ClearDiagnosticTraces()

	t.mu.Lock()
	t.inProgress = false
	t.progress.ElapsedMs = time.Since(startTime).Milliseconds()
	t.mu.Unlock()

	return nil
}

// Pause temporarily suspends testing. In-flight tests will complete.
func (t *ProxyTester) Pause() {
	t.pauseCond.L.Lock()
	t.paused = true
	t.pauseCond.L.Unlock()
}

// Resume resumes a paused testing session.
func (t *ProxyTester) Resume() {
	t.pauseCond.L.Lock()
	t.paused = false
	t.pauseCond.Broadcast()
	t.pauseCond.L.Unlock()
}

// Stop cancels the testing session and releases resources.
func (t *ProxyTester) Stop() {
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
	}
	t.mu.Unlock()
	t.Resume() // Ensure paused goroutines wake up to exit
}

// Results returns the current list of test results.
// Results are safe to read while testing is in progress.
func (t *ProxyTester) Results() []*TestResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	res := make([]*TestResult, len(t.results))
	copy(res, t.results)
	return res
}

// Progress returns the current testing progress snapshot.
func (t *ProxyTester) Progress() *TestProgress {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.progress
	return &p
}

// testSingle tests a single proxy and returns its result.
// It starts a temporary core instance, measures latency, optionally runs
// speed and GeoIP tests, and computes a composite score.
func (t *ProxyTester) testSingle(ctx context.Context, proxy *ProxyConfig) *TestResult {
	return t.testSingleOnPort(ctx, proxy, 20000)
}

// testSingleOnPort tests a single proxy on the specified SOCKS5 port.
func (t *ProxyTester) testSingleOnPort(ctx context.Context, proxy *ProxyConfig, socksPort int) *TestResult {
	result := &TestResult{
		Proxy:  proxy,
		Status: "failed",
	}

	if proxy.Address == "" {
		result.Status = "error"
		result.Error = "empty proxy address"
		return result
	}

	// Resolve hostname securely before pre-check and core execution
	resolvedHost := proxy.Address
	if t.config.DnsResolver != "" {
		ips, err := resolveHostsSecurely(proxy.Address, t.config.DnsResolver)
		if err == nil && len(ips) > 0 {
			resolvedHost = ips[0]
		}
	}

	// Create a mutated proxy configuration pointing directly to the clean IP address
	targetProxy := *proxy
	targetProxy.Address = resolvedHost

	// Fast pre-check: try a TCP connection or TLS handshake to the proxy address and port first.
	// This avoids launching expensive xray/singbox processes for dead servers.
	dialAddr := net.JoinHostPort(resolvedHost, fmt.Sprintf("%d", proxy.Port))
	checkDialer := &net.Dialer{
		Timeout: 2000 * time.Millisecond,
	}

	if proxy.TLS {
		// Do a fast TLS handshake check if TLS is enabled
		// Use utls to avoid standard Go crypto/tls fingerprinting
		uConn, err := checkDialer.Dial("tcp", dialAddr)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("pre-check connection failed: %v", err)
			return result
		}
		
		serverName := proxy.Address
		if proxy.SNI != "" {
			serverName = proxy.SNI
		}
		
		tlsConfig := &utls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		}
		
		// Use Chrome fingerprint
		utlsConn := utls.UClient(uConn, tlsConfig, utls.HelloChrome_Auto)
		if err := utlsConn.Handshake(); err != nil {
			uConn.Close()
			result.Status = "failed"
			result.Error = fmt.Sprintf("pre-check utls handshake failed: %v", err)
			return result
		}
		utlsConn.Close()
	} else {
		// Do a fast TCP connect check
		conn, err := checkDialer.DialContext(ctx, "tcp", dialAddr)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("pre-check connection failed: %v", err)
			return result
		}
		conn.Close()
	}

	// Start temporary core instance with the resolved proxy config
	inst, err := t.coreManager.RunTempInstance(&targetProxy, socksPort)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("failed to start core instance: %v", err)
		return result
	}
	defer inst.Stop()

	// Create SOCKS5 dialer using golang.org/x/net/proxy
	dialer, err := netproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, netproxy.Direct)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("failed to create SOCKS5 dialer: %v", err)
		return result
	}

	// Setup HTTP Client
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := dialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			if t.config.DiagnosticsEnabled {
				conn = NewDiagnosticConn(conn)
			}
			if t.config.SimulatePoorNetwork {
				loss := t.config.LossRate
				lat := time.Duration(t.config.LatencyMs) * time.Millisecond
				jit := time.Duration(t.config.JitterMs) * time.Millisecond
				conn = NewLossyConn(conn, loss, lat, jit)
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(t.config.Timeout) * time.Second,
	}

	// Test latency against configured TestURLs
	var latencies []float64
	allOk := true

	for _, urlStr := range t.config.TestURLs {
		urlLatencies := []float64{}
		runs := t.config.StabilityRuns
		if runs <= 0 {
			runs = 1
		}

		for run := 0; run < runs; run++ {
			tReq0 := time.Now()
			req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
			if err != nil {
				allOk = false
				result.Error = fmt.Sprintf("failed to create request: %v", err)
				break
			}
			req.Header.Set("User-Agent", "LumiNet/1.0")

			resp, err := client.Do(req)
			if err != nil {
				allOk = false
				result.Error = err.Error()
				break
			}
			resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 400 {
				allOk = false
				result.Error = fmt.Sprintf("HTTP status %d", resp.StatusCode)
				break
			}

			elapsed := time.Since(tReq0).Seconds() * 1000.0
			urlLatencies = append(urlLatencies, elapsed)
		}

		if !allOk {
			break
		}
		latencies = append(latencies, urlLatencies...)
	}

	if !allOk || len(latencies) == 0 {
		result.Status = "failed"
		return result
	}

	// Calculate average latency
	var sum float64
	for _, l := range latencies {
		sum += l
	}
	avgLatency := sum / float64(len(latencies))
	result.Latency = avgLatency
	result.StabilityResults = latencies
	result.Status = "working"

	// GeoIP Enrichment
	if t.config.GeoIPEnabled {
		req, err := http.NewRequestWithContext(ctx, "GET", "http://ip-api.com/json/", nil)
		if err == nil {
			req.Header.Set("User-Agent", "LumiNet/1.0")
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					var geo GeoInfo
					if err := json.NewDecoder(resp.Body).Decode(&geo); err == nil {
						result.GeoInfo = &geo
					}
				}
			}
		}
	}

	// Speed Test
	if t.config.SpeedTestEnabled {
		// Download a small chunk from a known URL (e.g. speedtest)
		speedURL := "http://speedtest.tele2.net/1MB.zip"
		tStartSpeed := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", speedURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "LumiNet/1.0")
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					buf := make([]byte, 8192)
					downloaded := 0
					for {
						n, err := resp.Body.Read(buf)
						downloaded += n
						if err != nil {
							break
						}
						if time.Since(tStartSpeed) > 5*time.Second {
							break
						}
					}
					elapsed := time.Since(tStartSpeed).Seconds()
					if elapsed > 0.05 && downloaded > 0 {
						// DownloadSpeed in Mbps (Megabits per second)
						result.DownloadSpeed = (float64(downloaded) * 8.0) / (elapsed * 1000000.0)
					}
				}
			}
		}
	}

	// Calculate composite score
	// score = 50.0 + latency_score + speed_score
	// latency_score = max(0.0, min(40.0, 40.0 * (1.0 - (latency / 1000.0))))
	// speed_score = min(10.0, download_speed * 2.0)
	latScore := 40.0 * (1.0 - (result.Latency / 1000.0))
	if latScore < 0 {
		latScore = 0
	}
	if latScore > 40.0 {
		latScore = 40.0
	}
	speedScore := result.DownloadSpeed * 2.0
	if speedScore > 10.0 {
		speedScore = 10.0
	}
	result.Score = 50.0 + latScore + speedScore

	return result
}
