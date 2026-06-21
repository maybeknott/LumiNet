package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/bridge"
	"github.com/maybeknott/luminet/internal/diagnostics"
	"github.com/maybeknott/luminet/internal/proxy"
)

// runIcmpScan executes an ICMP sweep job.
func (m *JobManager) runIcmpScan(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		Targets []string          `json:"targets"`
		Config  bridge.ScanConfig `json:"config"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 20)
	return bridge.IcmpScan(payload.Targets, payload.Config)
}

// runPortScan executes a TCP port scan job.
func (m *JobManager) runPortScan(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		Target string            `json:"target"`
		Ports  []uint16          `json:"ports"`
		Config bridge.ScanConfig `json:"config"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	return bridge.PortScan(payload.Target, payload.Ports, payload.Config)
}

// runDnsScan executes a DNS resolution job.
func (m *JobManager) runDnsScan(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		Server     string `json:"server"`
		Domain     string `json:"domain"`
		RecordType string `json:"record_type"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	return bridge.DnsResolve(payload.Server, payload.Domain, payload.RecordType)
}

// runTlsScan executes a TLS handshake probe.
func (m *JobManager) runTlsScan(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		Target    string `json:"target"`
		Port      uint16 `json:"port"`
		TimeoutMs uint32 `json:"timeout_ms"`
		Sni       string `json:"sni"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	sni := payload.Sni
	if sni == "" {
		sni = payload.Target
	}
	return bridge.TlsHandshakeWithSni(payload.Target, payload.Port, sni, payload.TimeoutMs)
}

// runSniScan executes an SNI blocking detection job.
func (m *JobManager) runSniScan(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		Domain    string `json:"domain"`
		TimeoutMs uint32 `json:"timeout_ms"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	return bridge.SniDetect(payload.Domain, payload.TimeoutMs)
}

// runProxyTest executes a proxy connectivity test.
func (m *JobManager) runProxyTest(ctx context.Context, job *Job) (interface{}, error) {
	// Private structs to avoid circular dependencies with api package
	type jobGeoIPInfo struct {
		Country string `json:"country"`
		City    string `json:"city,omitempty"`
		ISP     string `json:"isp,omitempty"`
		ASN     string `json:"asn,omitempty"`
	}

	type jobProxyScanRowResponse struct {
		Index     int           `json:"index"`
		ProxyURI  string        `json:"proxy_uri"`
		Protocol  string        `json:"protocol"`
		Address   string        `json:"address"`
		Port      int           `json:"port"`
		Status    string        `json:"status"`
		LatencyMs float64       `json:"latency_ms"`
		SpeedMbps float64       `json:"speed_mbps,omitempty"`
		GeoIP     *jobGeoIPInfo `json:"geoip,omitempty"`
		Error     string        `json:"error,omitempty"`
	}

	var batchPayload struct {
		Proxies      []string `json:"proxies"`
		ProxyURI     string   `json:"proxy_uri"`
		ProxyAddr    string   `json:"proxy_addr"`
		URLs         []string `json:"urls"`
		Target       string   `json:"target"`
		Timeout      int      `json:"timeout"`
		TimeoutMs    uint32   `json:"timeout_ms"`
		Concurrency  int      `json:"concurrency"`
		SpeedTest    bool     `json:"speed_test"`
		GeoIP        bool     `json:"geoip"`
		CoreType     string   `json:"core_type"`
		DnsResolver  string   `json:"dns_resolver"`
	}

	if err := json.Unmarshal([]byte(job.Config), &batchPayload); err != nil {
		return nil, err
	}

	// We support proxies list or single proxy
	var proxyURIs []string
	isBatch := false
	if len(batchPayload.Proxies) > 0 {
		proxyURIs = batchPayload.Proxies
		isBatch = true
	} else if batchPayload.ProxyAddr != "" {
		proxyURIs = []string{batchPayload.ProxyAddr}
	} else if batchPayload.ProxyURI != "" {
		proxyURIs = []string{batchPayload.ProxyURI}
	}

	if len(proxyURIs) == 0 {
		return nil, fmt.Errorf("no proxy addresses or URIs provided in job config")
	}

	// Resolve parameters
	var urls []string
	if len(batchPayload.URLs) > 0 {
		urls = batchPayload.URLs
	} else if batchPayload.Target != "" {
		urls = []string{batchPayload.Target}
	} else {
		urls = []string{"http://cp.cloudflare.com/"}
	}

	timeoutSec := batchPayload.Timeout
	if timeoutSec <= 0 {
		if batchPayload.TimeoutMs > 0 {
			timeoutSec = int(batchPayload.TimeoutMs / 1000)
		} else {
			timeoutSec = 10
		}
	}

	concurrency := batchPayload.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}

	// Parse all proxy configs
	var parsedProxies []*proxy.ProxyConfig
	for _, uri := range proxyURIs {
		pConf, err := proxy.ParseProxyURI(uri)
		if err == nil && pConf != nil {
			parsedProxies = append(parsedProxies, pConf)
		} else {
			if pConf == nil {
				pConf = &proxy.ProxyConfig{Name: "Invalid Proxy URI"}
			}
			parsedProxies = append(parsedProxies, pConf)
		}
	}

	coreType := proxy.CoreTypeAuto
	switch strings.ToLower(batchPayload.CoreType) {
	case "xray":
		coreType = proxy.CoreTypeXray
	case "singbox", "sing-box":
		coreType = proxy.CoreTypeSingBox
	}

	coreMgr := proxy.NewCoreManager(coreType, "")
	testConfig := proxy.TestConfig{
		TestURLs:         urls,
		Timeout:          timeoutSec,
		Concurrency:      concurrency,
		SpeedTestEnabled: batchPayload.SpeedTest,
		GeoIPEnabled:     batchPayload.GeoIP,
		StabilityRuns:    1,
		DnsResolver:      batchPayload.DnsResolver,
	}

	tester := proxy.NewProxyTester(testConfig, coreMgr)

	// Update progress in background
	stopProgressChan := make(chan struct{})
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopProgressChan:
				return
			case <-ticker.C:
				p := tester.Progress()
				if p.Total > 0 {
					pct := (p.Completed * 100) / p.Total
					if pct >= 100 {
						pct = 99
					}
					m.UpdateProgress(job.ID, pct)
				}
			}
		}
	}()

	err := tester.Start(ctx, parsedProxies)
	close(stopProgressChan)
	if err != nil {
		return nil, err
	}

	results := tester.Results()

	// Convert test results to our responses
	var rows []jobProxyScanRowResponse
	for i, r := range results {
		if r == nil {
			continue
		}

		var geo *jobGeoIPInfo
		if r.GeoInfo != nil {
			geo = &jobGeoIPInfo{
				Country: r.GeoInfo.Country,
				City:    r.GeoInfo.City,
				ISP:     r.GeoInfo.ISP,
				ASN:     r.GeoInfo.ASN,
			}
		}

		proxyURI := ""
		if i < len(proxyURIs) {
			proxyURI = proxyURIs[i]
		} else if r.Proxy != nil {
			proxyURI = r.Proxy.ToURI()
		}

		protoStr := ""
		addrStr := ""
		portVal := 0
		if r.Proxy != nil {
			protoStr = string(r.Proxy.Protocol)
			addrStr = r.Proxy.Address
			portVal = r.Proxy.Port
		}

		rows = append(rows, jobProxyScanRowResponse{
			Index:     i,
			ProxyURI:  proxyURI,
			Protocol:  protoStr,
			Address:   addrStr,
			Port:      portVal,
			Status:    r.Status,
			LatencyMs: r.Latency,
			SpeedMbps: r.DownloadSpeed,
			GeoIP:     geo,
			Error:     r.Error,
		})
	}

	m.UpdateProgress(job.ID, 100)

	if isBatch {
		return rows, nil
	}

	if len(rows) > 0 {
		return rows[0], nil
	}

	return nil, fmt.Errorf("no results generated")
}

// runSpeedTest executes a download throughput test.
func (m *JobManager) runSpeedTest(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		URL       string `json:"url"`
		TimeoutMs uint32 `json:"timeout_ms"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 20)
	return bridge.SpeedTest(payload.URL, payload.TimeoutMs)
}

// runDiagnostic executes the 6-phase network audit pipeline.
func (m *JobManager) runDiagnostic(ctx context.Context, job *Job) (interface{}, error) {
	pipeline := diagnostics.NewPipeline()
	var diagResults []interface{}

	phases := []struct {
		id     int
		name   string
		mType  diagnostics.MetricType
		target string
	}{
		{1, "Local Interface Check", diagnostics.MetricPing, "127.0.0.1"},
		{2, "Gateway Connectivity", diagnostics.MetricPing, "1.1.1.1"},
		{3, "DNS Resolution Audit", diagnostics.MetricDNS, "google.com"},
		{4, "Protocol Handshake", diagnostics.MetricHTTP, "http://cp.cloudflare.com/"},
		{5, "Path Trace Analytics", diagnostics.MetricTraceRoute, "8.8.8.8"},
		{6, "Egress Throughput", diagnostics.MetricSpeedTest, ""},
		{7, "Reliable UDP ARQ Benchmark", diagnostics.MetricARQ, "loopback"},
		{8, "Browser Stealth & Anti-Fingerprint Audit", diagnostics.MetricStealth, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"},
		{9, "ISP Spoofing & ASN Check", diagnostics.MetricAsnSpoof, "1.1.1.1"},
	}

	for i, phase := range phases {
		m.UpdateProgress(job.ID, (i*100)/len(phases))

		res, pErr := pipeline.Run(ctx, &diagnostics.DiagnosticJob{
			Type:    phase.mType,
			Target:  phase.target,
			Timeout: 15 * time.Second,
		})

		phaseRes := map[string]interface{}{
			"phase":       phase.id,
			"name":        phase.name,
			"passed":      pErr == nil && (res != nil && res.Success),
			"message":     "Completed successfully",
			"duration_ms": 0,
		}

		if pErr != nil {
			phaseRes["passed"] = false
			phaseRes["message"] = pErr.Error()
		} else if res != nil {
			phaseRes["passed"] = res.Success
			phaseRes["message"] = res.RawOutput
			phaseRes["duration_ms"] = res.LatencyMs
		}

		diagResults = append(diagResults, phaseRes)

		// Publish incremental result via WebSocket
		if m.broadcaster != nil {
			m.broadcaster.Publish(JobEvent{
				JobID:     job.ID,
				Type:      "result",
				Data:      phaseRes,
				Timestamp: time.Now(),
			})
		}
	}
	return diagResults, nil
}

// runWgScan executes a WireGuard endpoint probe.
func (m *JobManager) runWgScan(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		IP         string `json:"ip"`
		Port       uint16 `json:"port"`
		TimeoutMs  uint32 `json:"timeout_ms"`
		PaddingLen uint32 `json:"padding_len"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	return bridge.WgProbe(payload.IP, payload.Port, payload.TimeoutMs, payload.PaddingLen)
}

// runCdnScan executes a CDN edge IP sweep job.
func (m *JobManager) runCdnScan(ctx context.Context, job *Job) (interface{}, error) {
	var payload struct {
		Targets     []string `json:"targets"`
		CdnHost     string   `json:"cdn_host"`
		SampleRate  int      `json:"sample_rate"` // e.g. 1 for Quick, 3 for Normal, 0 for Full
		TimeoutMs   uint32   `json:"timeout_ms"`
		Concurrency int      `json:"concurrency"`
	}
	if err := json.Unmarshal([]byte(job.Config), &payload); err != nil {
		return nil, err
	}
	if payload.CdnHost == "" {
		payload.CdnHost = "speed.cloudflare.com"
	}
	if payload.TimeoutMs == 0 {
		payload.TimeoutMs = 1500
	}
	if payload.Concurrency == 0 {
		payload.Concurrency = 50
	}

	m.UpdateProgress(job.ID, 10)

	// 1. Generate/Sample IPs from the subnets
	ips := diagnostics.GenerateCdnIPs(payload.Targets, payload.SampleRate)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no targets resolved to valid CDN IPs")
	}

	m.UpdateProgress(job.ID, 20)

	var mu sync.Mutex
	var results []diagnostics.CdnScanResult
	completed := 0
	total := len(ips)

	// 2. Run scan pool
	diagnostics.RunScanPool(ips, payload.Concurrency, func(ip string) {
		// check context cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		res := diagnostics.ScanCdnIPDetailed(ip, payload.CdnHost, time.Duration(payload.TimeoutMs)*time.Millisecond)

		mu.Lock()
		results = append(results, res)
		completed++
		pct := 20 + (completed*70)/total
		if pct > 95 {
			pct = 95
		}
		mu.Unlock()

		// Update progress periodically
		if completed%10 == 0 || completed == total {
			m.UpdateProgress(job.ID, pct)
		}
	})

	return results, nil
}
