package fronting

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// CovertTransportConfig defines connection parameters for covert fronted dialing.
type CovertTransportConfig struct {
	// TargetIP overrides the DNS-resolved IP (e.g. "216.239.38.120:443").
	TargetIP string

	// SNI is the Server Name Indication presented during TLS handshake (e.g. "google.com").
	SNI string

	// HostHeader is the HTTP Host header injected into requests (e.g. "www.googleapis.com").
	HostHeader string

	// InsecureSkipVerify bypasses strict certificate chain validation when necessary.
	InsecureSkipVerify bool

	// ConnectTimeout is the timeout for the TCP connection attempt.
	ConnectTimeout time.Duration
}

// HostRewriteTransport is an http.RoundTripper that rewrites request Host headers for domain fronting.
type HostRewriteTransport struct {
	Transport  http.RoundTripper
	HostHeader string
}

// RoundTrip executes a single HTTP transaction, rewriting the Host header if configured.
func (t *HostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.HostHeader != "" {
		req.Host = t.HostHeader
	}
	return t.Transport.RoundTrip(req)
}

// NewCovertHTTPClient constructs an http.Client with forced destination IP and SNI manipulation.
func NewCovertHTTPClient(cfg CovertTransportConfig) *http.Client {
	timeout := cfg.ConnectTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cfg.TargetIP != "" {
				return dialer.DialContext(ctx, "tcp", cfg.TargetIP)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	var rt http.RoundTripper = transport
	if cfg.HostHeader != "" {
		rt = &HostRewriteTransport{
			Transport:  transport,
			HostHeader: cfg.HostHeader,
		}
	}

	return &http.Client{
		Transport: rt,
		Timeout:   60 * time.Second,
	}
}
