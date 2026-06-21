//go:build !cgo

package bridge

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// MockMode indicates whether the bridge is a CGO-disabled mock version.
const MockMode = true

// IcmpScan mocks or runs a simple ICMP/TCP scan.
func IcmpScan(targets []string, config ScanConfig) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0, len(targets))
	for _, target := range targets {
		// Try to resolve target as a basic check
		ips, err := net.LookupHost(target)
		alive := err == nil
		ip := ""
		if len(ips) > 0 {
			ip = ips[0]
		}

		results = append(results, ProbeResult{
			Target:    target,
			IP:        ip,
			Alive:     alive,
			LatencyMs: 5.0,
			Timestamp: uint64(time.Now().Unix()),
			Metadata:  map[string]string{"mock": "true"},
		})
	}
	return results, nil
}

// TcpConnect performs a real TCP connection check in pure Go.
func TcpConnect(target string, port uint16, timeout uint32) (*ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Millisecond)
	latency := float64(time.Since(start).Milliseconds())

	if err != nil {
		return &ProbeResult{
			Target:    target,
			Port:      port,
			Alive:     false,
			LatencyMs: latency,
			Error:     err.Error(),
			ErrorCode: "CONNECTION_FAILED",
			Timestamp: uint64(time.Now().Unix()),
		}, nil
	}
	defer conn.Close()

	ip := ""
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcpAddr.IP.String()
	}

	return &ProbeResult{
		Target:    target,
		Port:      port,
		IP:        ip,
		Alive:     true,
		LatencyMs: latency,
		Timestamp: uint64(time.Now().Unix()),
		Metadata:  map[string]string{"mock": "true"},
	}, nil
}

// PortScan runs a concurrent port scan using pure Go net.Dial.
func PortScan(target string, ports []uint16, config ScanConfig) ([]PortResult, error) {
	results := make([]PortResult, len(ports))
	type sem struct{}
	limit := make(chan sem, config.Concurrency)

	for i, port := range ports {
		limit <- sem{}
		go func(idx int, p uint16) {
			defer func() { <-limit }()
			start := time.Now()
			addr := net.JoinHostPort(target, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, time.Duration(config.Timeout)*time.Millisecond)
			latency := float64(time.Since(start).Milliseconds())

			if err != nil {
				results[idx] = PortResult{
					IP:        target,
					Port:      p,
					Open:      false,
					Protocol:  "tcp",
					LatencyMs: latency,
				}
				return
			}
			conn.Close()

			results[idx] = PortResult{
				IP:        target,
				Port:      p,
				Open:      true,
				Protocol:  "tcp",
				LatencyMs: latency,
			}
		}(i, port)
	}

	// Wait for all goroutines to finish by filling the limit channel
	for i := 0; i < int(config.Concurrency); i++ {
		limit <- sem{}
	}

	return results, nil
}

// DnsResolve queries DNS in pure Go.
func DnsResolve(server, domain string, recordType string) (*DnsServerResult, error) {
	start := time.Now()
	// Use system resolver
	ips, err := net.LookupHost(domain)
	latency := float64(time.Since(start).Milliseconds())

	if err != nil {
		return &DnsServerResult{
			Server:    server,
			Protocol:  "udp",
			LatencyMs: latency,
			Success:   false,
			Error:     err.Error(),
		}, nil
	}

	records := make([]DnsRecord, 0, len(ips))
	for _, ip := range ips {
		records = append(records, DnsRecord{
			Name:  domain,
			Type:  "A",
			Value: ip,
			TTL:   3600,
			Class: "IN",
		})
	}

	return &DnsServerResult{
		Server:    server,
		Protocol:  "udp",
		LatencyMs: latency,
		Success:   true,
		Records:   records,
	}, nil
}

// TlsHandshake performs a real TLS handshake in Go.
func TlsHandshake(host string, port uint16, timeout uint32) (*TlsInfo, error) {
	return TlsHandshakeWithSni(host, port, host, timeout)
}

func TlsHandshakeWithSni(host string, port uint16, sni string, timeout uint32) (*TlsInfo, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var alpn []string
	if state.NegotiatedProtocol != "" {
		alpn = []string{state.NegotiatedProtocol}
	}

	subject := ""
	issuer := ""
	san := []string{}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		subject = cert.Subject.String()
		issuer = cert.Issuer.String()
		san = cert.DNSNames
	}

	return &TlsInfo{
		Version:     fmt.Sprintf("%x", state.Version),
		CipherSuite: fmt.Sprintf("%d", state.CipherSuite),
		CertIssuer:  issuer,
		CertSubject: subject,
		ALPN:        alpn,
		SanDomains:  san,
		ChainLength: len(state.PeerCertificates),
	}, nil
}

// Socks5Probe mocks SOCKS5 proxy check.
func Socks5Probe(proxy string, target string, timeout uint32) (*ProbeResult, error) {
	return &ProbeResult{
		Target:    target,
		Alive:     false,
		Error:     "SOCKS5 FFI probe not supported in CGO-disabled mock mode",
		ErrorCode: "UNSUPPORTED",
		Timestamp: uint64(time.Now().Unix()),
	}, nil
}

// HttpGet performs an HTTP request using Go's http.Client.
func HttpGet(rawUrl string, timeout uint32, proxy string) (*HttpResponse, error) {
	start := time.Now()

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	if proxy != "" {
		proxyUrl, err := url.Parse(proxy)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			}
		}
	}

	resp, err := client.Get(rawUrl)
	latency := float64(time.Since(start).Milliseconds())

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &HttpResponse{
		StatusCode: resp.StatusCode,
		LatencyMs:  latency,
		Redirected: false,
		FinalURL:   rawUrl,
	}, nil
}

// SniDetect mocks SNI detection check.
func SniDetect(domain string, timeout uint32) (*SniResult, error) {
	return nil, fmt.Errorf("SNI detection is not supported in mock mode")
}

// SpeedTest mocks a speed test response.
func SpeedTest(url string, timeoutMs uint32) (*SpeedResult, error) {
	return nil, fmt.Errorf("speed test is not supported in mock mode")
}

// ExpandTargets expands CIDR using standard Go net package.
func ExpandTargets(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for IPv4 if it's a typical subnet
	if len(ips) > 2 && !ip.To4().Equal(nil) {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// WgProbe mocks WireGuard probe check.
func WgProbe(ip string, port uint16, timeoutMs uint32, paddingLen uint32) (*ProbeResult, error) {
	return &ProbeResult{
		Target:    ip,
		Port:      port,
		Alive:     false,
		Error:     "WireGuard FFI probe not supported in CGO-disabled mock mode",
		ErrorCode: "UNSUPPORTED",
		Timestamp: uint64(time.Now().Unix()),
	}, nil
}

// CaptivePortalProbe mocks captive portal check.
func CaptivePortalProbe(timeoutMs uint32) (string, error) {
	return `"Open"`, nil
}

// PadClientHello pads a TLS ClientHello record (pure Go implementation).
func PadClientHello(rawHex string, padLen int) (string, error) {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", err
	}
	if len(raw) < 43 {
		return "", fmt.Errorf("ClientHello too short")
	}
	if raw[0] != 0x16 {
		return "", fmt.Errorf("Not a handshake record")
	}
	if raw[5] != 0x01 {
		return "", fmt.Errorf("Not a ClientHello handshake")
	}

	offset := 43
	sessionIDLen := int(raw[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(raw) {
		return "", fmt.Errorf("Malformed ClientHello: session ID bounds")
	}

	cipherSuitesLen := int(raw[offset])<<8 | int(raw[offset+1])
	offset += 2 + cipherSuitesLen
	if offset+1 > len(raw) {
		return "", fmt.Errorf("Malformed ClientHello: cipher suites bounds")
	}

	compressionLen := int(raw[offset])
	offset += 1 + compressionLen

	hasExtensions := offset+2 <= len(raw)

	var result []byte
	extBlockAddedLen := 4 + padLen // 2 bytes type + 2 bytes len + padLen zeros

	if hasExtensions {
		extensionsLen := int(raw[offset])<<8 | int(raw[offset+1])
		if offset+2+extensionsLen > len(raw) {
			return "", fmt.Errorf("Malformed ClientHello: extensions bounds")
		}

		result = append(result, raw[0:3]...)
		oldRecLen := int(raw[3])<<8 | int(raw[4])
		newRecLen := oldRecLen + extBlockAddedLen
		result = append(result, byte(newRecLen>>8), byte(newRecLen&0xff))

		result = append(result, raw[5]) // Handshake type

		oldHsLen := int(raw[6])<<16 | int(raw[7])<<8 | int(raw[8])
		newHsLen := oldHsLen + extBlockAddedLen
		result = append(result, byte(newHsLen>>16), byte((newHsLen>>8)&0xff), byte(newHsLen&0xff))

		result = append(result, raw[9:offset]...)

		newExtLen := extensionsLen + extBlockAddedLen
		result = append(result, byte(newExtLen>>8), byte(newExtLen&0xff))

		result = append(result, raw[offset+2:offset+2+extensionsLen]...)

		// Append padding extension: type 0x0015 (21), length padLen, then padLen zeros
		result = append(result, 0x00, 0x15)
		result = append(result, byte(padLen>>8), byte(padLen&0xff))
		result = append(result, make([]byte, padLen)...)

		result = append(result, raw[offset+2+extensionsLen:]...)
	} else {
		result = append(result, raw[0:3]...)
		oldRecLen := int(raw[3])<<8 | int(raw[4])
		newRecLen := oldRecLen + 2 + extBlockAddedLen
		result = append(result, byte(newRecLen>>8), byte(newRecLen&0xff))

		result = append(result, raw[5])

		oldHsLen := int(raw[6])<<16 | int(raw[7])<<8 | int(raw[8])
		newHsLen := oldHsLen + 2 + extBlockAddedLen
		result = append(result, byte(newHsLen>>16), byte((newHsLen>>8)&0xff), byte(newHsLen&0xff))

		result = append(result, raw[9:offset]...)

		result = append(result, byte(extBlockAddedLen>>8), byte(extBlockAddedLen&0xff))

		// Append padding extension
		result = append(result, 0x00, 0x15)
		result = append(result, byte(padLen>>8), byte(padLen&0xff))
		result = append(result, make([]byte, padLen)...)
	}

	return hex.EncodeToString(result), nil
}

// InjectFakePacket mocks sending a custom raw TCP packet (no-op in mock mode).
func InjectFakePacket(targetIp string, port uint16, ttl uint32, flags *uint8, seq *uint32, ack *uint32, payloadHex string) error {
	return nil
}

