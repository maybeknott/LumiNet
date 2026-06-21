package system

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// HardenedCipherSuites defines the collection of secure TLS 1.2/1.3 cipher suites
// enforced by the client system.
var HardenedCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// GetHardenedTLSConfig returns a tls.Config object configured to enforce TLS 1.2 and TLS 1.3
// with curated modern cipher suites.
func GetHardenedTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		ServerName:               serverName,
		CipherSuites:             HardenedCipherSuites,
		PreferServerCipherSuites: true,
	}
}

// CheckLocalTorProxy checks if Orbot or a local Tor service is running on SOCKS ports 9050 or 9150.
func CheckLocalTorProxy() (string, bool) {
	ports := []string{"127.0.0.1:9050", "127.0.0.1:9150"}
	for _, addr := range ports {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return addr, true
		}
	}
	return "", false
}

// NewHardenedHttpClient creates a net/http Client hardened against downgrade attacks
// and configured with a timeout boundary.
func NewHardenedHttpClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       GetHardenedTLSConfig(""),
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// DialUTLS establishes an outbound TLS connection utilizing the uTLS library
// to mimic a specific browser TLS ClientHello handshake signature.
func DialUTLS(network, address string, serverName string, clientHelloID utls.ClientHelloID) (net.Conn, error) {
	tcpConn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		return nil, err
	}

	uConn := utls.UClient(tcpConn, &utls.Config{ServerName: serverName}, clientHelloID)
	if err := uConn.Handshake(); err != nil {
		uConn.Close()
		return nil, err
	}

	return uConn, nil
}
