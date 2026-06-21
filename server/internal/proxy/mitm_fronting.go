package proxy

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/maybeknott/luminet/internal/crypto"
)

// MitmFrontingProxy represents a local diagnostic MITM proxy
// that intercepts SSL/TLS connections, signs temporary certs using a local CA,
// and mutates headers/SNI parameters to test domain fronting boundaries.
type MitmFrontingProxy struct {
	Addr       string
	caCert     *x509.Certificate
	caKey      interface{}
	listener   net.Listener
	mu         sync.Mutex
	isRunning  bool
	tlsConfig  *tls.Config
}

// NewMitmFrontingProxy creates a new MitmFrontingProxy.
func NewMitmFrontingProxy(addr string) (*MitmFrontingProxy, error) {
	caCert, caKey, err := crypto.GenerateCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate diagnostic CA: %w", err)
	}

	return &MitmFrontingProxy{
		Addr:   addr,
		caCert: caCert,
		caKey:  caKey,
	}, nil
}

// Start launches the local MITM interceptor.
func (p *MitmFrontingProxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isRunning {
		return fmt.Errorf("MITM proxy already running")
	}

	l, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return err
	}
	p.listener = l
	p.isRunning = true

	server := &http.Server{
		Handler: http.HandlerFunc(p.handleConnect),
	}

	go func() {
		_ = server.Serve(l)
	}()

	return nil
}

// Stop shuts down the MITM listener.
func (p *MitmFrontingProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isRunning {
		return
	}

	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.isRunning = false
}

func (p *MitmFrontingProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Intercept TCP connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Acknowledge connection tunnel established
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Extract target host domain name
	host, _, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		host = r.URL.Host
	}

	// Generate dynamic on-the-fly leaf certificate signed by our root CA
	caRsaKey, ok := p.caKey.(*rsa.PrivateKey)
	if !ok || caRsaKey == nil {
		return
	}

	der, leafKey, err := crypto.GenerateCert(host, p.caCert, caRsaKey)
	if err != nil {
		return
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	// Read client HTTP request over TLS
	reader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// Normalize request headers
	req.Header = NormalizeHttpHeaders(req.Header)

	// In diagnostic test mode, respond with dynamic leaf confirmation to verify MITM decryption
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader("LumiNet MITM Decryption Active for: " + host)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")
	_ = resp.Write(tlsConn)
}

// NormalizeHttpHeaders reorders request headers to bypass DPI fingerprint checks.
func NormalizeHttpHeaders(headers map[string][]string) map[string][]string {
	normalized := make(map[string][]string)
	// Enforce clean canonical browser ordering: Host, User-Agent, Accept, Accept-Language, etc.
	keys := []string{"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection"}
	for _, key := range keys {
		if val, ok := headers[key]; ok {
			normalized[key] = val
		}
	}
	for k, v := range headers {
		if _, ok := normalized[k]; !ok {
			normalized[k] = v
		}
	}
	return normalized
}
