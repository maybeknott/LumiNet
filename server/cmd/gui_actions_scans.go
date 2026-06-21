//go:build windows && cgo

package cmd

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func (s *nativeShell) startNativeScan() {
	modeIndex := 0
	if s.scanMode != nil && s.scanMode.CurrentIndex() >= 0 {
		modeIndex = s.scanMode.CurrentIndex()
	}
	targetText := ""
	if s.scanTarget != nil {
		targetText = strings.TrimSpace(s.scanTarget.Text())
	}
	if targetText == "" && s.cockpitTarget != nil {
		targetText = strings.TrimSpace(s.cockpitTarget.Text())
	}
	if targetText == "" {
		s.setStatus("Enter at least one scan target.")
		return
	}

	timeout := 3000
	if s.scanTimeout != nil {
		timeout = parsePositiveInt(s.scanTimeout.Text(), 3000)
	}
	concurrency := 100
	if s.scanConcurrency != nil {
		concurrency = parsePositiveInt(s.scanConcurrency.Text(), 100)
	}
	recordTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}
	recordType := recordTypes[0]
	if s.scanRecordType != nil {
		if idx := s.scanRecordType.CurrentIndex(); idx >= 0 && idx < len(recordTypes) {
			recordType = recordTypes[idx]
		}
	}
	ports := "80,443,8443"
	if s.scanPorts != nil && strings.TrimSpace(s.scanPorts.Text()) != "" {
		ports = s.scanPorts.Text()
	}
	dnsServer := "1.1.1.1"
	if s.scanDNSServer != nil && strings.TrimSpace(s.scanDNSServer.Text()) != "" {
		dnsServer = strings.TrimSpace(s.scanDNSServer.Text())
	}
	ipv6 := false
	if s.scanIPv6 != nil {
		ipv6 = s.scanIPv6.Checked()
	}
	s.launchNativeScan(modeIndex, targetText, ports, dnsServer, recordType, timeout, concurrency, ipv6)
}

func (s *nativeShell) launchNativeScan(modeIndex int, targetText, portsText, dnsServer, recordType string, timeout, concurrency int, ipv6 bool) {
	if recordType == "" {
		recordType = "A"
	}

	endpoint := "/api/scans"
	var payload map[string]interface{}
	modeName := "ICMP sweep"
	switch modeIndex {
	case 0:
		payload = map[string]interface{}{
			"targets":     splitTargets(targetText),
			"timeout":     timeout,
			"concurrency": concurrency,
			"ipv6":        ipv6,
		}
	case 1:
		endpoint = "/api/port-scans"
		ports, err := parsePortList(portsText)
		if err != nil {
			s.setStatus("Port scan input failed: " + err.Error())
			return
		}
		modeName = "TCP port scan"
		payload = map[string]interface{}{
			"target":      firstTarget(targetText),
			"ports":       ports,
			"timeout":     timeout,
			"concurrency": concurrency,
		}
	case 2:
		endpoint = "/api/dns-scans"
		modeName = "DNS record scan"
		payload = map[string]interface{}{
			"domain":      firstTarget(targetText),
			"server":      strings.TrimSpace(dnsServer),
			"record_type": recordType,
			"timeout_ms":  timeout,
		}
	case 3:
		endpoint = "/api/tls-scans"
		modeName = "TLS handshake scan"
		tlsPayload := map[string]interface{}{
			"target":     firstTarget(targetText),
			"port":       firstPortOrDefault(portsText, 443),
			"timeout_ms": timeout,
		}
		if s.scanSni != nil && strings.TrimSpace(s.scanSni.Text()) != "" {
			tlsPayload["sni"] = strings.TrimSpace(s.scanSni.Text())
		}
		payload = tlsPayload
	case 4:
		endpoint = "/api/sni-scans"
		modeName = "SNI check"
		payload = map[string]interface{}{
			"domain":     firstTarget(targetText),
			"timeout_ms": timeout,
		}
	case 5:
		endpoint = "/api/tls-scans"
		modeName = "CDN IP sweep"
		payload = map[string]interface{}{
			"mode":        "cdn_sweep",
			"targets":     splitTargets(targetText),
			"timeout_ms":  timeout,
			"concurrency": concurrency,
			"sample_rate": 1, // Quick mode by default
		}
		if s.scanSni != nil && strings.TrimSpace(s.scanSni.Text()) != "" {
			payload["sni"] = strings.TrimSpace(s.scanSni.Text())
		}
	case 6:
		endpoint = "/api/diagnostics"
		modeName = "ASN Spoof check"
		payload = map[string]interface{}{
			"type":   "asn_spoof",
			"target": firstTarget(targetText),
		}
	}

	go func() {
		body, _ := json.Marshal(payload)
		var result map[string]interface{}
		err := s.postJSON(endpoint, body, &result)
		s.sync(func() {
			if err != nil {
				s.appendLog(modeName + " failed: " + err.Error())
				s.setStatus("Scan launch failed.")
				return
			}
			s.appendLog(fmt.Sprintf("Started %s. Job: %v", modeName, result["id"]))
			s.setStatus(modeName + " started.")
			s.refreshStatus()
			s.refreshHistory()
		})
	}()
}

func (s *nativeShell) benchmarkAndLoadIPs(presets []string, providerName string) {
	if s.scanTarget == nil {
		return
	}
	s.setStatus(fmt.Sprintf("Benchmarking %s subnets to find clean/active IPs...", providerName))

	go func() {
		var allSampledIPs []string
		for _, cidr := range presets {
			allSampledIPs = append(allSampledIPs, sampleCIDRIPs(cidr, 4)...)
		}

		if len(allSampledIPs) == 0 {
			s.sync(func() {
				s.setStatus("Failed to parse subnet presets.")
			})
			return
		}

		activeIPs := probeIPsConcurrently(allSampledIPs, 30, 800*time.Millisecond)

		s.sync(func() {
			if s.scanTarget == nil {
				return
			}
			if len(activeIPs) > 0 {
				s.scanTarget.SetText(strings.Join(activeIPs, ","))
				s.setStatus(fmt.Sprintf("Benchmarks done! Loaded %d active %s IPs.", len(activeIPs), providerName))
			} else {
				// Fallback to static CIDRs
				s.scanTarget.SetText(strings.Join(presets, ","))
				s.setStatus(fmt.Sprintf("No active IPs found on port 443. Loaded static %s subnets as fallback.", providerName))
			}
		})
	}()
}

func (s *nativeShell) loadCloudflareIPs() {
	presets := []string{
		"104.16.0.0/12", "172.64.0.0/13", "162.158.0.0/15", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"141.101.64.0/18", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "104.24.0.0/14",
	}
	s.benchmarkAndLoadIPs(presets, "Cloudflare")
}

func (s *nativeShell) loadAkamaiIPs() {
	presets := []string{
		"2.16.0.0/13", "2.17.0.0/16", "2.18.0.0/16", "2.19.0.0/16",
		"23.32.0.0/11", "23.64.0.0/14", "184.24.0.0/13", "184.84.0.0/14",
		"96.16.0.0/12", "104.64.0.0/11", "23.200.0.0/13",
	}
	s.benchmarkAndLoadIPs(presets, "Akamai")
}

func (s *nativeShell) loadFastlyIPs() {
	presets := []string{
		"151.101.0.0/16", "199.232.0.0/16", "199.27.72.0/21", "192.147.24.0/24",
		"167.99.0.0/16", "185.199.108.0/22",
	}
	s.benchmarkAndLoadIPs(presets, "Fastly")
}

func (s *nativeShell) loadGCoreIPs() {
	presets := []string{
		"92.223.0.0/16", "92.38.0.0/16", "95.140.0.0/16", "188.116.0.0/16",
		"5.188.0.0/16", "146.185.0.0/16",
	}
	s.benchmarkAndLoadIPs(presets, "GCore")
}

func (s *nativeShell) loadWarpIPs() {
	presets := []string{
		"8.6.112.0/24", "8.34.70.0/24", "8.34.146.0/24", "8.35.211.0/24", "8.39.125.0/24",
		"8.39.204.0/24", "8.39.214.0/24", "8.47.69.0/24", "162.159.192.0/24", "162.159.195.0/24",
		"188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
	}
	s.benchmarkAndLoadIPs(presets, "WARP")
}

func sampleCIDRIPs(cidr string, sampleSize int) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return []string{ip.String()}
	}

	isIPv4 := ip.To4() != nil
	if isIPv4 {
		totalHosts := uint32(1) << hostBits
		step := totalHosts / uint32(sampleSize)
		if step == 0 {
			step = 1
		}
		ipv4Val := binary.BigEndian.Uint32(ip.To4())
		for i := 0; i < sampleSize; i++ {
			offset := uint32(i)*step + 2
			if offset >= totalHosts {
				break
			}
			sampledIPVal := ipv4Val + offset
			sampledIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(sampledIP, sampledIPVal)
			ips = append(ips, sampledIP.String())
		}
	} else {
		for i := 0; i < sampleSize; i++ {
			sampledIP := make(net.IP, 16)
			copy(sampledIP, ip)
			sampledIP[15] += byte(i + 1)
			ips = append(ips, sampledIP.String())
		}
	}
	return ips
}

func probeIPsConcurrently(ips []string, concurrency int, timeout time.Duration) []string {
	var activeIPs []string
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		sem <- struct{}{}
		wg.Add(1)
		go func(targetIP string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			addr := net.JoinHostPort(targetIP, "443")
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				activeIPs = append(activeIPs, targetIP)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return activeIPs
}
