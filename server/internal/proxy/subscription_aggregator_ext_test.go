package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func generateSelfSignedCertForReality() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LumiNet Test"},
			CommonName:   "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func TestRealityScanner(t *testing.T) {
	// Generate self-signed certificate for the mock TLS 1.3 server
	cert, err := generateSelfSignedCertForReality()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	// Mock server loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	addr := listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	// Run scanner check
	targets := []ScanTarget{
		{Address: host, Port: port},
	}
	results, err := ScanRealityTargets(context.Background(), targets, 1, 1*time.Second)
	if err != nil {
		t.Fatalf("ScanRealityTargets failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	t.Logf("Scan result: Compatible=%v, TLSVersion=%x, CipherSuite=%x, ALPN=%q, Error=%q",
		res.Compatible, res.TLSVersion, res.CipherSuite, res.ALPN, res.Error)

	// Self-signed certificate names should be checked and matching
	if res.TLSVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 (0x0304), got %x", res.TLSVersion)
	}
}

func TestFilterSafeProxyConfig(t *testing.T) {
	cases := []struct {
		addr string
		safe bool
	}{
		{"127.0.0.1", false},
		{"192.168.1.1", false},
		{"10.0.0.5", false},
		{"localhost", false},
		{"test.local", false},
		{"example.com", true},
		{"8.8.8.8", true},
	}
	for _, tc := range cases {
		cfg := &ProxyConfig{Address: tc.addr}
		if FilterSafeProxyConfig(cfg) != tc.safe {
			t.Errorf("address %q expected safe=%v, got %v", tc.addr, tc.safe, !tc.safe)
		}
	}
}

func TestSubconvert(t *testing.T) {
	proxies := []*ProxyConfig{
		{
			Protocol: ProtocolVLESS,
			Address:  "example.com",
			Port:     443,
			UUID:     "uuid-1234",
			Name:     "VlessTest",
		},
	}
	clash, err := Subconvert(proxies, "clash")
	if err != nil {
		t.Fatalf("Subconvert clash failed: %v", err)
	}
	if !strings.Contains(clash, "vless") || !strings.Contains(clash, "example.com") {
		t.Errorf("invalid Clash output: %s", clash)
	}

	base64Sub, err := Subconvert(proxies, "base64")
	if err != nil {
		t.Fatalf("Subconvert base64 failed: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(base64Sub)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") {
		t.Errorf("invalid subscription output: %s", string(decoded))
	}
}
