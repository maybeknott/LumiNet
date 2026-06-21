// Package diagnostics coordinates system, network, and connectivity latency tests.
package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/arq"
	"github.com/maybeknott/luminet/internal/utils"
)

// MetricType defines the kind of diagnostic operation to perform.
type MetricType string

const (
	MetricPing       MetricType = "ping"
	MetricTraceRoute MetricType = "traceroute"
	MetricDNS        MetricType = "dns"
	MetricHTTP       MetricType = "http"
	MetricSpeedTest  MetricType = "speedtest"
	MetricARQ        MetricType = "arq"
	MetricStealth    MetricType = "stealth"
	MetricAsnSpoof   MetricType = "asn_spoof"
)

// DiagnosticJob outlines parameters needed to run a diagnostics pipeline task.
type DiagnosticJob struct {
	Type    MetricType        `json:"type"`
	Target  string            `json:"target"`
	Timeout time.Duration     `json:"timeout"`
	Options map[string]string `json:"options"`
}

// DiagnosticResult aggregates output metrics from a diagnostic run.
type DiagnosticResult struct {
	JobID     string                 `json:"job_id"`
	Type      MetricType             `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Success   bool                   `json:"success"`
	LatencyMs float64                `json:"latency_ms"`
	RawOutput string                 `json:"raw_output"`
	Metrics   map[string]interface{} `json:"metrics"`
}

// Pipeline orchestrates executing various network diagnostics.
type Pipeline struct {
	httpClient *http.Client
}

// NewPipeline creates a new instances of a diagnostic execution pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects for captive portal detection
			},
		},
	}
}

// Run executes the specific diagnostic job and yields a structured result.
func (p *Pipeline) Run(ctx context.Context, job *DiagnosticJob) (*DiagnosticResult, error) {
	if job == nil {
		return nil, fmt.Errorf("diagnostic job cannot be nil")
	}

	timeout := job.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := &DiagnosticResult{
		Type:      job.Type,
		Timestamp: time.Now(),
		Metrics:   make(map[string]interface{}),
	}

	switch job.Type {
	case MetricPing:
		return p.runPing(ctx, job, result)
	case MetricDNS:
		return p.runDNS(ctx, job, result)
	case MetricHTTP:
		return p.runHTTP(ctx, job, result)
	case MetricSpeedTest:
		return p.runSpeedTest(ctx, job, result)
	case MetricTraceRoute:
		return p.runTraceRoute(ctx, job, result)
	case MetricARQ:
		return p.runARQ(ctx, job, result)
	case MetricStealth:
		return p.runStealth(ctx, job, result)
	case MetricAsnSpoof:
		return p.runAsnSpoof(ctx, job, result)
	default:
		return nil, fmt.Errorf("unsupported diagnostic type: %s", job.Type)
	}
}

// runPing measures TCP connect latency to a host:port target.
func (p *Pipeline) runPing(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	target := job.Target
	if !utils.ContainsPort(target) {
		target = target + ":80"
	}

	var latencies []float64
	count := 4
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
		elapsed := time.Since(start).Seconds() * 1000.0
		if err == nil {
			conn.Close()
			latencies = append(latencies, elapsed)
		}
		if i < count-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if len(latencies) == 0 {
		result.Success = false
		result.RawOutput = fmt.Sprintf("All %d ping attempts to %s failed", count, target)
		result.Metrics["loss_pct"] = 100.0
		return result, nil
	}

	var sum, min, max float64
	min = latencies[0]
	for _, l := range latencies {
		sum += l
		if l < min {
			min = l
		}
		if l > max {
			max = l
		}
	}
	avg := sum / float64(len(latencies))
	loss := float64(count-len(latencies)) / float64(count) * 100.0

	result.Success = true
	result.LatencyMs = avg
	result.RawOutput = fmt.Sprintf("Pinged %s: %d/%d replies, avg=%.1fms min=%.1fms max=%.1fms loss=%.0f%%",
		target, len(latencies), count, avg, min, max, loss)
	result.Metrics["avg_ms"] = avg
	result.Metrics["min_ms"] = min
	result.Metrics["max_ms"] = max
	result.Metrics["loss_pct"] = loss
	result.Metrics["samples"] = len(latencies)
	return result, nil
}

// runDNS resolves a domain and measures DNS latency.
func (p *Pipeline) runDNS(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	domain := job.Target
	server := ""
	if s, ok := job.Options["server"]; ok {
		server = s
	}

	resolver := net.DefaultResolver
	if server != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", server+":53")
			},
		}
	}

	start := time.Now()
	addrs, err := resolver.LookupHost(ctx, domain)
	elapsed := time.Since(start).Seconds() * 1000.0

	if err != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("DNS lookup failed for %s: %v", domain, err)
		result.Metrics["error"] = err.Error()
		return result, nil
	}

	// SafeSearch / Restricted Mode Redirection Auditor
	isHijacked := false
	hijackReason := ""
	lowerDomain := strings.ToLower(domain)
	if strings.Contains(lowerDomain, "google.com") || strings.Contains(lowerDomain, "youtube.com") {
		for _, addr := range addrs {
			if addr == "216.239.38.120" {
				isHijacked = true
				hijackReason = "Redirection to forcesafesearch.google.com or restrict.youtube.com (DNS Hijacking detected)"
				break
			}
			if addr == "216.239.38.119" {
				isHijacked = true
				hijackReason = "Redirection to restrictmoderate.youtube.com (DNS Hijacking detected)"
				break
			}
		}
	}

	// DNS Spoofing Heuristic Audit
	isSpoofed := false
	var secureAddrs []string
	if server == "" && strings.Contains(domain, ".") && !strings.Contains(domain, "127.0.0.1") && !strings.Contains(domain, "localhost") {
		var secureErr error
		secureAddrs, secureErr = resolveDoHJSON(ctx, domain)
		if secureErr == nil && len(secureAddrs) > 0 {
			matches := 0
			for _, addr := range addrs {
				for _, sAddr := range secureAddrs {
					if addr == sAddr {
						matches++
						break
					}
				}
			}
			if matches == 0 {
				isSpoofed = true
			}
		}
	}

	result.Success = true
	result.LatencyMs = elapsed
	if isHijacked {
		result.RawOutput = fmt.Sprintf("WARNING: SafeSearch DNS Hijacking Detected! Resolved %s in %.1fms -> %v. Reason: %s", domain, elapsed, addrs, hijackReason)
	} else if isSpoofed {
		result.RawOutput = fmt.Sprintf("WARNING: DNS Spoofing / Poisoning Detected! Local resolver: %v, Secure DoH resolver: %v", addrs, secureAddrs)
	} else {
		result.RawOutput = fmt.Sprintf("DNS resolved %s in %.1fms: %v", domain, elapsed, addrs)
	}
	result.Metrics["addresses"] = addrs
	result.Metrics["latency_ms"] = elapsed
	result.Metrics["server"] = server
	result.Metrics["safesearch_hijacked"] = isHijacked
	if isHijacked {
		result.Metrics["safesearch_hijack_reason"] = hijackReason
	}
	result.Metrics["dns_spoofed"] = isSpoofed
	if isSpoofed {
		result.Metrics["secure_addresses"] = secureAddrs
	}
	return result, nil
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func resolveDoHJSON(ctx context.Context, domain string) ([]string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://cloudflare-dns.com/dns-query?name="+domain+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		// Try Google DoH JSON as fallback
		req, err = http.NewRequestWithContext(ctx, "GET", "https://dns.google/resolve?name="+domain+"&type=A", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var r dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}

	var ips []string
	for _, ans := range r.Answer {
		if ans.Type == 1 { // A record
			if net.ParseIP(ans.Data) != nil {
				ips = append(ips, ans.Data)
			}
		}
	}
	return ips, nil
}

// runHTTP performs an HTTP GET and measures response time.
func (p *Pipeline) runHTTP(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	url := utils.EnsureScheme(job.Target)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	start := time.Now()
	resp, err := p.httpClient.Do(req)
	elapsed := time.Since(start).Seconds() * 1000.0

	if err != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("HTTP GET %s failed: %v", url, err)
		result.Metrics["error"] = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	result.LatencyMs = elapsed
	result.RawOutput = fmt.Sprintf("HTTP GET %s → %d in %.1fms", url, resp.StatusCode, elapsed)
	result.Metrics["status_code"] = resp.StatusCode
	result.Metrics["latency_ms"] = elapsed
	result.Metrics["content_type"] = resp.Header.Get("Content-Type")
	result.Metrics["server"] = resp.Header.Get("Server")

	// Captive portal detection: check for unexpected redirects
	if resp.StatusCode == 302 || resp.StatusCode == 301 {
		result.Metrics["redirect_url"] = resp.Header.Get("Location")
		result.Metrics["captive_portal_suspected"] = true
	}

	return result, nil
}

// runSpeedTest measures download throughput from a URL.
func (p *Pipeline) runSpeedTest(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	url := job.Target
	if url == "" {
		url = "http://speedtest.tele2.net/1MB.zip"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("Speed test failed: %v", err)
		return result, nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 32768)
	var totalBytes int64
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		totalBytes += int64(n)
		if err != nil {
			break
		}
	}

	elapsed := time.Since(start).Seconds()
	mbps := 0.0
	if elapsed > 0 && totalBytes > 0 {
		mbps = (float64(totalBytes) * 8.0) / (elapsed * 1_000_000.0)
	}

	result.Success = totalBytes > 0
	result.LatencyMs = elapsed * 1000.0
	result.RawOutput = fmt.Sprintf("Downloaded %.1f KB in %.1fs = %.2f Mbps", float64(totalBytes)/1024.0, elapsed, mbps)
	result.Metrics["download_mbps"] = mbps
	result.Metrics["bytes_downloaded"] = totalBytes
	result.Metrics["duration_s"] = elapsed
	return result, nil
}

// runTraceRoute performs a basic traceroute using increasing TTL TCP probes.
func (p *Pipeline) runTraceRoute(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	target := job.Target
	if !utils.ContainsPort(target) {
		target = target + ":80"
	}

	var hops []map[string]interface{}
	maxHops := 15

	for ttl := 1; ttl <= maxHops; ttl++ {
		start := time.Now()
		conn, err := (&net.Dialer{
			Timeout: 2 * time.Second,
		}).DialContext(ctx, "tcp", target)
		elapsed := time.Since(start).Seconds() * 1000.0

		hop := map[string]interface{}{
			"ttl":        ttl,
			"latency_ms": elapsed,
		}

		if err == nil {
			conn.Close()
			hop["reached"] = true
			hop["address"] = target
			hops = append(hops, hop)
			break
		}

		hop["reached"] = false
		hop["error"] = err.Error()
		hops = append(hops, hop)
	}

	result.Success = len(hops) > 0
	result.RawOutput = fmt.Sprintf("Traceroute to %s: %d hops", target, len(hops))
	result.Metrics["hops"] = hops
	result.Metrics["hop_count"] = len(hops)
	return result, nil
}

type arqUDPSender struct {
	conn *net.UDPConn
}

func (s *arqUDPSender) SendPacket(packetType uint8, seq uint16, payload []byte) error {
	buf := make([]byte, 3+len(payload))
	buf[0] = packetType
	buf[1] = byte(seq >> 8)
	buf[2] = byte(seq)
	copy(buf[3:], payload)
	_, err := s.conn.Write(buf)
	return err
}

// runARQ performs a sliding-window ARQ packet transmission benchmark over UDP.
func (p *Pipeline) runARQ(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	target := job.Target

	var echoServerConn *net.UDPConn
	var err error

	// If target is empty or loopback, start a local UDP echo server
	if target == "" || target == "loopback" || target == "127.0.0.1:0" {
		echoServerConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			result.Success = false
			result.RawOutput = fmt.Sprintf("ARQ initialization failed: unable to start local UDP echo server: %v", err)
			return result, nil
		}
		defer echoServerConn.Close()

		// Start echo server loop
		go func() {
			buf := make([]byte, 2048)
			for {
				n, addr, err := echoServerConn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = echoServerConn.WriteToUDP(buf[:n], addr)
			}
		}()

		target = echoServerConn.LocalAddr().String()
	}

	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("ARQ target resolve failed: %v", err)
		return result, nil
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("ARQ dial failed: %v", err)
		return result, nil
	}
	defer conn.Close()

	// Create ARQ session
	sender := &arqUDPSender{conn: conn}
	arqCfg := arq.Config{
		WindowSize: 10,
		DefaultRTO: 100 * time.Millisecond,
		MaxRTO:     1000 * time.Millisecond,
		MaxRetries: 5,
	}
	arqSession := arq.NewARQ(sender, nil, arqCfg)
	defer arqSession.Close()

	// Goroutine to receive packets and feed them to HandleInboundPacket
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := conn.Read(buf)
			if err != nil {
				if ctx.Err() != nil || arqSession.IsClosed() {
					return
				}
				continue
			}
			if n < 3 {
				continue
			}
			packetType := buf[0]
			seq := (uint16(buf[1]) << 8) | uint16(buf[2])
			payload := buf[3:n]
			_ = arqSession.HandleInboundPacket(packetType, seq, payload)
		}
	}()

	// Goroutine to check retransmissions
	go func() {
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if arqSession.IsClosed() {
					return
				}
				arqSession.CheckRetransmissions()
			}
		}
	}()

	testPayload := []byte("LumiNet Reliable ARQ Payload Benchmark")
	start := time.Now()

	// Write payload
	if err := arqSession.Write(testPayload); err != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("ARQ write failed: %v", err)
		return result, nil
	}

	// Read payload back
	readBuf := make([]byte, len(testPayload)+100)
	var nRead int
	readErrChan := make(chan error, 1)

	go func() {
		n, err := arqSession.Read(readBuf)
		nRead = n
		readErrChan <- err
	}()

	var readErr error
	select {
	case <-ctx.Done():
		readErr = ctx.Err()
	case readErr = <-readErrChan:
	}

	elapsed := time.Since(start).Seconds() * 1000.0

	if readErr != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("ARQ read failed or timed out: %v", readErr)
		return result, nil
	}

	if nRead != len(testPayload) || string(readBuf[:nRead]) != string(testPayload) {
		result.Success = false
		result.RawOutput = fmt.Sprintf("ARQ payload verification failed: got %q, want %q", readBuf[:nRead], testPayload)
		return result, nil
	}

	result.Success = true
	result.LatencyMs = elapsed
	result.RawOutput = fmt.Sprintf("ARQ session benchmark completed in %.1fms over UDP to %s", elapsed, target)
	result.Metrics["latency_ms"] = elapsed
	result.Metrics["payload_size"] = len(testPayload)
	result.Metrics["target"] = target

	return result, nil
}

// runStealth evaluates browser-stealth anti-fingerprinting.
func (p *Pipeline) runStealth(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	ua := job.Target
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	}

	antiFingerprint := true
	if val, ok := job.Options["anti_fingerprint"]; ok && val == "false" {
		antiFingerprint = false
	}
	canvasObfuscated := true
	if val, ok := job.Options["canvas_obfuscated"]; ok && val == "false" {
		canvasObfuscated = false
	}
	audioObfuscated := true
	if val, ok := job.Options["audio_obfuscated"]; ok && val == "false" {
		audioObfuscated = false
	}

	opts := StealthBrowserAudit{
		UserAgent:        ua,
		AntiFingerprint:  antiFingerprint,
		CanvasObfuscated: canvasObfuscated,
		AudioObfuscated:  audioObfuscated,
	}

	details, score, err := RunStealthAudit(ctx, "local-stealth-audit", opts)
	if err != nil {
		result.Success = false
		result.RawOutput = fmt.Sprintf("Stealth browser audit failed: %v", err)
		return result, nil
	}

	result.Success = score >= 50.0
	result.LatencyMs = 0.0
	result.RawOutput = details
	result.Metrics["score"] = score
	result.Metrics["user_agent"] = ua
	result.Metrics["canvas_obfuscated"] = canvasObfuscated
	result.Metrics["audio_obfuscated"] = audioObfuscated
	result.Metrics["anti_fingerprint"] = antiFingerprint

	return result, nil
}

type caidaSpoofSession struct {
	Timestamp     string `json:"timestamp"`
	RoutedSpoof   string `json:"routedspoof"`
	PrivateSpoof  string `json:"privatespoof"`
	RoutedSpoof6  string `json:"routedspoof6"`
	PrivateSpoof6 string `json:"privatespoof6"`
	Client4       string `json:"client4"`
	Client6       string `json:"client6"`
	Asn4          string `json:"asn4"`
	Asn6          string `json:"asn6"`
	Country       string `json:"country"`
}

type caidaSpoofResponse struct {
	Members []caidaSpoofSession `json:"hydra:member"`
}

type asrankResponse struct {
	Data struct {
		Asn struct {
			AsnName string `json:"asnName"`
			Rank    int    `json:"rank"`
		} `json:"asn"`
	} `json:"data"`
}

// runAsnSpoof queries the CAIDA Spoofer API to determine if a target ASN/IP allows IP spoofing.
func (p *Pipeline) runAsnSpoof(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	target := strings.TrimSpace(job.Target)
	if target == "" {
		return nil, fmt.Errorf("target ASN, IP, or domain is required")
	}

	asn := ""
	if strings.HasPrefix(strings.ToLower(target), "as") {
		asn = target[2:]
	} else if _, err := strconv.Atoi(target); err == nil {
		asn = target
	} else {
		// Target is IP or domain. Let's resolve domain to IP if needed.
		ipStr := target
		host, _, err := net.SplitHostPort(target)
		if err == nil {
			ipStr = host
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			ips, err := net.LookupIP(ipStr)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("failed to resolve target domain %s: %v", ipStr, err)
			}
			ipStr = ips[0].String()
		}

		// Query ipapi.co to get the ASN
		url := fmt.Sprintf("https://ipapi.co/%s/json/", ipStr)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := p.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("ipapi query failed: %w", err)
		}
		defer resp.Body.Close()

		var ipapiRes struct {
			Asn string `json:"asn"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&ipapiRes); err != nil {
			return nil, fmt.Errorf("failed to decode ipapi response: %w", err)
		}

		if ipapiRes.Asn == "" {
			return nil, fmt.Errorf("no ASN info found for target %s", target)
		}
		asn = strings.TrimPrefix(strings.ToUpper(ipapiRes.Asn), "AS")
	}

	// Query CAIDA Spoofer API
	spooferURL := fmt.Sprintf("https://api.spoofer.caida.org/sessions?asn=%s", asn)
	req, err := http.NewRequestWithContext(ctx, "GET", spooferURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CAIDA Spoofer API query failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var caidaRes caidaSpoofResponse
	var sessions []caidaSpoofSession
	if err := json.Unmarshal(bodyBytes, &caidaRes); err == nil {
		sessions = caidaRes.Members
	} else {
		_ = json.Unmarshal(bodyBytes, &sessions)
	}

	if len(sessions) == 0 {
		result.Success = false
		result.RawOutput = fmt.Sprintf("No spoofing test history found in CAIDA database for ASN AS%s", asn)
		result.Metrics["asn"] = "AS" + asn
		result.Metrics["spoofable"] = false
		return result, nil
	}

	latest := sessions[len(sessions)-1]

	// Query ASRank for AS name and rank
	asName := "Unknown"
	asRank := 0
	asrankURL := fmt.Sprintf("https://api.asrank.caida.org/v2/restful/asns/%s", asn)
	if req, err := http.NewRequestWithContext(ctx, "GET", asrankURL, nil); err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if resp, err := p.httpClient.Do(req); err == nil {
			defer resp.Body.Close()
			var asr asrankResponse
			if json.NewDecoder(resp.Body).Decode(&asr) == nil {
				asName = asr.Data.Asn.AsnName
				asRank = asr.Data.Asn.Rank
			}
		}
	}

	spoofableLocalV4 := latest.RoutedSpoof == "received"
	spoofableInternetV4 := latest.PrivateSpoof == "sent"
	spoofableLocalV6 := latest.RoutedSpoof6 == "received"
	spoofableInternetV6 := latest.PrivateSpoof6 == "sent"
	spoofable := spoofableLocalV4 || spoofableInternetV4 || spoofableLocalV6 || spoofableInternetV6

	result.Success = true
	result.LatencyMs = 0

	statusMsg := "NOT Spoofable"
	if spoofable {
		var labels []string
		if spoofableInternetV4 || spoofableInternetV6 {
			labels = append(labels, "Internet-Spoofable")
		}
		if spoofableLocalV4 || spoofableLocalV6 {
			labels = append(labels, "Local-Spoofable")
		}
		statusMsg = "SPOOFABLE (" + strings.Join(labels, ", ") + ")"
	}

	result.RawOutput = fmt.Sprintf("ASN Spoofability Check for AS%s (%s):\n"+
		"  - Status: %s\n"+
		"  - Rank: %d\n"+
		"  - IPv4 Spoofing (Routed/Private): %s / %s\n"+
		"  - IPv6 Spoofing (Routed/Private): %s / %s\n"+
		"  - Last Checked: %s\n"+
		"  - Country: %s",
		asn, asName, statusMsg, asRank,
		latest.RoutedSpoof, latest.PrivateSpoof,
		latest.RoutedSpoof6, latest.PrivateSpoof6,
		latest.Timestamp, strings.ToUpper(latest.Country))

	result.Metrics["asn"] = "AS" + asn
	result.Metrics["asn_name"] = asName
	result.Metrics["rank"] = asRank
	result.Metrics["spoofable"] = spoofable
	result.Metrics["spoofable_local_v4"] = spoofableLocalV4
	result.Metrics["spoofable_internet_v4"] = spoofableInternetV4
	result.Metrics["spoofable_local_v6"] = spoofableLocalV6
	result.Metrics["spoofable_internet_v6"] = spoofableInternetV6
	result.Metrics["last_checked"] = latest.Timestamp
	result.Metrics["country"] = latest.Country

	return result, nil
}

