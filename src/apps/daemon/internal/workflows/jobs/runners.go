package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
	"github.com/maybeknott/luminet/internal/analysis/scanner"
	"github.com/maybeknott/luminet/internal/native/bridge"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
	"github.com/maybeknott/luminet/internal/runtime/proxy"
)

// runIcmpScan executes an ICMP sweep job.
func (m *JobManager) runIcmpScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[IcmpScanIntent](job)
	if err != nil {
		return nil, err
	}
	config := bridge.ScanConfig{Timeout: uint32(payload.TimeoutMs), Concurrency: uint32(payload.Concurrency), RateLimitPPS: 1000, RetryCount: 1, AdaptiveRate: true, IPv6: payload.IPv6}
	m.UpdateProgress(job.ID, 20)
	return bridge.IcmpScan(payload.Targets, config)
}

// runPortScan executes a TCP port scan job.
func (m *JobManager) runPortScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[PortScanIntent](job)
	if err != nil {
		return nil, err
	}
	config := bridge.ScanConfig{Timeout: uint32(payload.TimeoutMs), Concurrency: uint32(payload.Concurrency), RateLimitPPS: 1000, RetryCount: 1, AdaptiveRate: false}
	m.UpdateProgress(job.ID, 30)
	return bridge.PortScan(payload.Target, payload.Ports, config)
}

// runDnsScan executes a DNS resolution job.
func (m *JobManager) runDnsScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[DnsScanIntent](job)
	if err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	return bridge.DnsResolveWithTimeout(payload.Server, payload.Domain, payload.RecordType, payload.TimeoutMs)
}

// runTlsScan executes a TLS handshake probe.
func (m *JobManager) runTlsScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[TlsScanIntent](job)
	if err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	sni := payload.SNI
	if sni == "" {
		sni = payload.Target
	}
	return bridge.TlsHandshakeWithSni(payload.Target, payload.Port, sni, payload.TimeoutMs)
}

// runSniScan executes an SNI blocking detection job.
func (m *JobManager) runSniScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[SniScanIntent](job)
	if err != nil {
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

	batchPayload, err := intentAs[ProxyTestIntent](job)
	if err != nil {
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
	var parsedProxies []*proxyconfig.ProxyConfig
	for _, uri := range proxyURIs {
		pConf, err := proxyconfig.ParseProxyURI(uri)
		if err == nil && pConf != nil {
			parsedProxies = append(parsedProxies, pConf)
		} else {
			if pConf == nil {
				pConf = &proxyconfig.ProxyConfig{Name: "Invalid Proxy URI"}
			}
			parsedProxies = append(parsedProxies, pConf)
		}
	}

	results, err := proxy.Qualify(ctx, proxy.QualificationRequest{
		Proxies:       parsedProxies,
		Core:          batchPayload.CoreType,
		TestURLs:      urls,
		Timeout:       timeoutSec,
		Concurrency:   concurrency,
		SpeedTest:     batchPayload.SpeedTest,
		GeoIP:         batchPayload.GeoIP,
		DNSResolver:   batchPayload.DNSResolver,
		StabilityRuns: 1,
	}, func(p proxy.TestProgress) {
		if p.Total <= 0 {
			return
		}
		pct := (p.Completed * 100) / p.Total
		if pct >= 100 {
			pct = 99
		}
		m.UpdateProgress(job.ID, pct)
	})
	if err != nil {
		return nil, err
	}

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
	payload, err := intentAs[SpeedTestIntent](job)
	if err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 20)
	return bridge.SpeedTest(payload.URL, payload.TimeoutMs)
}

// runDiagnostic executes either one requested diagnostic or the full audit pipeline.
func (m *JobManager) runDiagnostic(ctx context.Context, job *Job) (interface{}, error) {
	config, err := intentAs[DiagnosticIntent](job)
	if err != nil {
		return nil, err
	}
	plan, single, err := buildDiagnosticPlan(config)
	if err != nil {
		return nil, err
	}
	pipeline := diagnostics.NewPipeline()

	if single {
		phase := plan[0]
		m.UpdateProgress(job.ID, 10)
		result, runErr := pipeline.Run(ctx, &diagnostics.DiagnosticJob{
			Type:    phase.metric,
			Target:  phase.target,
			Timeout: phase.timeout,
			Options: cloneStringMap(phase.options),
		})
		if runErr != nil {
			return nil, runErr
		}
		m.UpdateProgress(job.ID, 90)
		m.publishEvent(JobEvent{JobID: job.ID, Type: "result", Data: result, Timestamp: time.Now()})
		return result, nil
	}

	diagnosticResults := make([]interface{}, 0, len(plan))
	for index, phase := range plan {
		m.UpdateProgress(job.ID, (index*100)/len(plan))
		result, runErr := pipeline.Run(ctx, &diagnostics.DiagnosticJob{
			Type:    phase.metric,
			Target:  phase.target,
			Timeout: phase.timeout,
			Options: cloneStringMap(phase.options),
		})

		phaseResult := map[string]interface{}{
			"phase":       phase.id,
			"name":        phase.name,
			"passed":      runErr == nil && result != nil && result.Success,
			"message":     "Completed successfully",
			"duration_ms": 0,
		}

		if runErr != nil {
			phaseResult["passed"] = false
			phaseResult["message"] = runErr.Error()
		} else if result != nil {
			phaseResult["passed"] = result.Success
			phaseResult["message"] = result.RawOutput
			phaseResult["duration_ms"] = result.LatencyMs

			if suspected, ok := result.Metrics["captive_portal_suspected"].(bool); ok && suspected {
				redirectURL, _ := result.Metrics["redirect_url"].(string)
				if redirectURL != "" {
					m.publishEvent(JobEvent{JobID: job.ID, Type: "event_captive_portal_detected", Data: map[string]string{"redirect_url": redirectURL}, Timestamp: time.Now()})
				}
			}
		}

		diagnosticResults = append(diagnosticResults, phaseResult)
		m.publishEvent(JobEvent{JobID: job.ID, Type: "result", Data: phaseResult, Timestamp: time.Now()})
	}
	return diagnosticResults, nil
}

// runWgScan executes a WireGuard endpoint probe.
func (m *JobManager) runWgScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[WgScanIntent](job)
	if err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 30)
	return bridge.WgProbe(payload.IP, payload.Port, payload.TimeoutMs, payload.PaddingLen)
}

// runCdnScan executes a CDN edge IP sweep job.
func (m *JobManager) runCdnScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[CdnScanIntent](job)
	if err != nil {
		return nil, err
	}
	m.UpdateProgress(job.ID, 10)
	ips, err := diagnostics.GeneratePublicCdnIPs(payload.Targets, payload.SampleRate)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no targets resolved to valid CDN IPs")
	}
	m.UpdateProgress(job.ID, 20)
	var mu sync.Mutex
	var results []diagnostics.CdnScanResult
	completed := 0
	total := len(ips)
	diagnostics.RunScanPool(ips, payload.Concurrency, func(ip string) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		res := diagnostics.ScanCdnIPDetailed(ip, payload.CDNHost, time.Duration(payload.TimeoutMs)*time.Millisecond)
		mu.Lock()
		results = append(results, res)
		completed++
		current := completed
		pct := 20 + (current*70)/total
		if pct > 95 {
			pct = 95
		}
		mu.Unlock()
		if current%10 == 0 || current == total {
			_ = m.UpdateProgress(job.ID, pct)
		}
	})
	return results, nil
}

// runIpDiscovery executes an IP discovery sweep.
func (m *JobManager) runIpDiscovery(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[IpDiscoveryIntent](job)
	if err != nil {
		return nil, err
	}
	if len(payload.Blocks) == 0 {
		return nil, fmt.Errorf("no cidr blocks provided")
	}
	scanner := scanner.NewIPDiscoveryScanner(payload.Blocks, time.Duration(payload.TimeoutMs)*time.Millisecond)
	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(payload.Duration)*time.Second)
	defer cancel()
	scanner.Start(scanCtx, payload.Workers)
	defer scanner.Stop()
	var discovered []string
	for {
		select {
		case <-scanCtx.Done():
			return discovered, nil
		case ip := <-scanner.Results():
			discovered = append(discovered, ip)
			m.publishEvent(JobEvent{JobID: job.ID, Type: "result", Data: ip, Timestamp: time.Now()})
		}
	}
}

// runStreamScan executes a real-time reactive streaming scan via lumicore.
// It connects streaming.go directly into JobManager.Broadcaster() for sub-millisecond,
// reactive event delivery to WebSocket clients.
func (m *JobManager) runStreamScan(ctx context.Context, job *Job) (interface{}, error) {
	payload, err := intentAs[StreamScanIntent](job)
	if err != nil {
		return nil, err
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	streamCh, cancelFunc, err := bridge.StartStream(1, rawPayload)
	if err != nil {
		return nil, err
	}
	defer cancelFunc()

	var collectedResults []bridge.StreamProbeResultData
	_ = m.UpdateProgress(job.ID, 10)

	for {
		select {
		case <-ctx.Done():
			cancelFunc()
			return collectedResults, ctx.Err()
		case evt, ok := <-streamCh:
			if !ok {
				_ = m.UpdateProgress(job.ID, 100)
				return collectedResults, nil
			}
			switch evt.Type {
			case bridge.StreamEvtProbeResult:
				probe, err := bridge.ParseStreamProbeResult(evt.Data)
				if err == nil {
					collectedResults = append(collectedResults, probe)
					m.Broadcaster().Publish(JobEvent{
						JobID:     job.ID,
						Type:      "probe_result",
						Data:      probe,
						Timestamp: time.Now(),
					})
				}
			case bridge.StreamEvtPoolUpdate:
				prog, err := bridge.ParseStreamProgress(evt.Data)
				if err == nil {
					_ = m.UpdateProgress(job.ID, int(prog.Percent))
					m.Broadcaster().Publish(JobEvent{
						JobID:     job.ID,
						Type:      "progress",
						Data:      prog,
						Timestamp: time.Now(),
					})
				}
			case bridge.StreamEvtScanDone:
				_ = m.UpdateProgress(job.ID, 100)
				return collectedResults, nil
			case bridge.StreamEvtError:
				errMsg := string(evt.Data)
				m.Broadcaster().Publish(JobEvent{
					JobID:     job.ID,
					Type:      "error",
					Data:      errMsg,
					Timestamp: time.Now(),
				})
				return collectedResults, fmt.Errorf("stream scan error: %s", errMsg)
			}
		}
	}
}

