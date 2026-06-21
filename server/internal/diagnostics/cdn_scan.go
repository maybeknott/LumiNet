package diagnostics

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// CdnScanResult represents the detailed result of scanning a CDN edge IP.
type CdnScanResult struct {
	IP        string  `json:"ip"`
	Alive     bool    `json:"alive"`
	LatencyMs float64 `json:"latency_ms"`
	HTTPCode  int     `json:"http_code,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// ScanCdnIP sweeps edge IP subnet ranges to discover unblocked servers for domain fronting.
func ScanCdnIP(ip string, testHost string) bool {
	dialer := &net.Dialer{Timeout: 1 * time.Second}
	uConn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}

	tlsConfig := &utls.Config{
		ServerName:         testHost,
		InsecureSkipVerify: true,
	}

	utlsConn := utls.UClient(uConn, tlsConfig, utls.HelloChrome_Auto)
	if err := utlsConn.Handshake(); err != nil {
		uConn.Close()
		return false
	}
	defer utlsConn.Close()
	return true
}
// ScanCdnIPDetailed performs a detailed TLS handshake and HTTP fronting test on a CDN edge IP.
func ScanCdnIPDetailed(ip string, testHost string, timeout time.Duration) CdnScanResult {
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}

	// 1. Verify TLS Handshake
	uConn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return CdnScanResult{
			IP:    ip,
			Alive: false,
			Error: err.Error(),
		}
	}
	
	tlsConfig := &utls.Config{
		ServerName:         testHost,
		InsecureSkipVerify: true,
	}
	
	utlsConn := utls.UClient(uConn, tlsConfig, utls.HelloChrome_Auto)
	if err := utlsConn.Handshake(); err != nil {
		uConn.Close()
		return CdnScanResult{
			IP:    ip,
			Alive: false,
			Error: err.Error(),
		}
	}
	utlsConn.Close()

	latency := time.Since(start).Seconds() * 1000.0

	// 2. Verify HTTP Fronting / Cloudflare header verification
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
				if err != nil {
					return nil, err
				}
				clientConf := &utls.Config{
					ServerName:         testHost,
					InsecureSkipVerify: true,
				}
				tlsConn := utls.UClient(rawConn, clientConf, utls.HelloChrome_Auto)
				if err := tlsConn.Handshake(); err != nil {
					rawConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", testHost), nil)
	if err != nil {
		return CdnScanResult{
			IP:        ip,
			Alive:     true,
			LatencyMs: latency,
		}
	}
	req.Host = testHost
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return CdnScanResult{
			IP:        ip,
			Alive:     true,
			LatencyMs: latency,
			Error:     "http verification failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return CdnScanResult{
		IP:        ip,
		Alive:     true,
		LatencyMs: latency,
		HTTPCode:  resp.StatusCode,
	}
}

// GenerateCdnIPs parses a list of CIDRs and returns a list of sampled/expanded IPs.
// sampleRate: number of IPs to sample per /24 block (e.g. 1 for quick, 3 for normal, 0 for all).
func GenerateCdnIPs(cidrs []string, sampleRate int) []string {
	var ips []string
	for _, cidr := range cidrs {
		cidr = fmt.Sprintf("%v", cidr) // sanitize interface/type if needed
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			// If it's a single IP, just add it
			if net.ParseIP(cidr) != nil {
				ips = append(ips, cidr)
			}
			continue
		}

		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}

		maskOnes, _ := ipnet.Mask.Size()
		if maskOnes > 24 {
			// Subnet is smaller than /24, just add all IPs in it
			expanded, _ := expandCIDR(cidr)
			ips = append(ips, expanded...)
			continue
		}

		// Iterate over all /24 blocks in the subnet
		startIPVal := binary.BigEndian.Uint32(ip4)
		maskVal := binary.BigEndian.Uint32(ipnet.Mask)
		networkVal := startIPVal & maskVal
		broadcastVal := networkVal | ^maskVal

		// A /24 has 256 addresses. Let's step by 256
		for subVal := networkVal; subVal < broadcastVal; subVal += 256 {
			if sampleRate <= 0 {
				// Full: add all 256 IPs (excluding .0 and .255 usually)
				for host := 1; host < 255; host++ {
					targetVal := subVal + uint32(host)
					ips = append(ips, valToIP(targetVal))
				}
			} else {
				// Sample sampleRate IPs from this /24 block
				for i := 0; i < sampleRate; i++ {
					// Use a deterministic/pseudo-random offset to ensure we get different IPs
					offset := (i * (254 / sampleRate)) + 1 + (int(subVal) % 7)
					if offset > 254 {
						offset = 254
					}
					targetVal := subVal + uint32(offset)
					ips = append(ips, valToIP(targetVal))
				}
			}
		}
	}
	return ips
}

func valToIP(val uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip.String()
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == 255 {
			ip[i] = 0
			continue
		}
		ip[i]++
		break
	}
}
