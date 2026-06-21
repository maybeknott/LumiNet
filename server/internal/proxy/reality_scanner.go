package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ScanTarget holds a destination address and port for REALITY compatibility checking.
type ScanTarget struct {
	Address string
	Port    int
}

// ScanResult contains details about the target's TLS support.
type ScanResult struct {
	Target      ScanTarget    `json:"target"`
	Compatible  bool          `json:"compatible"`
	TLSVersion  uint16        `json:"tls_version"`
	CipherSuite uint16        `json:"cipher_suite"`
	ALPN        string        `json:"alpn"`
	CertSubject string        `json:"cert_subject"`
	CertIssuer  string        `json:"cert_issuer"`
	Latency     time.Duration `json:"latency"`
	Error       string        `json:"error,omitempty"`
}

// ScanRealityTargets runs parallel scanning over multiple targets checking for REALITY fallback capability.
func ScanRealityTargets(ctx context.Context, targets []ScanTarget, concurrency int, timeout time.Duration) ([]ScanResult, error) {
	if concurrency <= 0 {
		concurrency = 10
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	queue := make(chan ScanTarget, len(targets))
	for _, t := range targets {
		queue <- t
	}
	close(queue)

	results := make([]ScanResult, 0, len(targets))
	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	// Rotate scanner User-Agent client hello fingerprints
	fingerprints := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloSafari_Auto,
		utls.HelloEdge_Auto,
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range queue {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Insert random scan intervals to prevent target detection campaigns
				nBig, err := rand.Int(rand.Reader, big.NewInt(30))
				var delay int64 = 10
				if err == nil {
					delay = nBig.Int64() + 5
				}
				time.Sleep(time.Duration(delay) * time.Millisecond)

				// Choose a random fingerprint
				fIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(fingerprints))))
				idx := 0
				if err == nil {
					idx = int(fIdx.Int64())
				}

				res := ScanSingleReality(ctx, target, fingerprints[idx], timeout)

				resultsMu.Lock()
				results = append(results, res)
				resultsMu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// ScanSingleReality runs a single TLS handshake check and parses negotiated parameters.
func ScanSingleReality(ctx context.Context, target ScanTarget, helloID utls.ClientHelloID, timeout time.Duration) ScanResult {
	res := ScanResult{
		Target:     target,
		Compatible: false,
	}

	dialAddr := net.JoinHostPort(target.Address, fmt.Sprintf("%d", target.Port))
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	t0 := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		res.Error = fmt.Sprintf("dial failed: %v", err)
		return res
	}
	defer conn.Close()

	res.Latency = time.Since(t0)

	// Configure TLS client hello matching targets SNI
	tlsConfig := &utls.Config{
		ServerName:         target.Address,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(conn, tlsConfig, helloID)
	err = uConn.Handshake()
	if err != nil {
		res.Error = fmt.Sprintf("handshake failed: %v", err)
		return res
	}

	state := uConn.ConnectionState()
	res.TLSVersion = state.Version
	res.CipherSuite = state.CipherSuite
	res.ALPN = state.NegotiatedProtocol

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		res.CertSubject = cert.Subject.String()
		res.CertIssuer = cert.Issuer.String()

		// Filter certificates to prevent malicious redirects/loops
		if len(cert.DNSNames) > 0 {
			match := false
			for _, name := range cert.DNSNames {
				if strings.Contains(strings.ToLower(target.Address), strings.ToLower(name)) ||
					strings.Contains(strings.ToLower(name), strings.ToLower(target.Address)) {
					match = true
					break
				}
			}
			if !match && !strings.EqualFold(cert.Subject.CommonName, target.Address) {
				res.Error = "certificate name mismatch: target address does not match certificate common name or alternative names"
				return res
			}
		}
	}

	// REALITY destinations must support TLS 1.3 (0x0304) and ALPN
	if res.TLSVersion == utls.VersionTLS13 && res.ALPN != "" {
		res.Compatible = true
	}

	return res
}
