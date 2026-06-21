package system

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ECHResolver fetches Encrypted Client Hello (ECH) keys dynamically
// using secure asynchronous DNS queries (SVCB/HTTPS/TXT records).
type ECHResolver struct {
	dnsServer string
	timeout   time.Duration
}

// NewECHResolver creates an ECHResolver instance.
func NewECHResolver(dnsServer string, timeout time.Duration) *ECHResolver {
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}
	return &ECHResolver{
		dnsServer: dnsServer,
		timeout:   timeout,
	}
}

// ResolveECHConfigList resolves the ECH configuration list for the target domain
// by querying TXT/SVCB/HTTPS records.
func (r *ECHResolver) ResolveECHConfigList(ctx context.Context, domain string) ([]byte, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, "udp", r.dnsServer)
		},
	}

	txts, err := resolver.LookupTXT(ctx, "_ech."+domain)
	if err == nil && len(txts) > 0 {
		for _, txt := range txts {
			data, err := base64.StdEncoding.DecodeString(txt)
			if err == nil && len(data) > 0 {
				return data, nil
			}
		}
	}

	return nil, fmt.Errorf("no ECH config found for domain: %s", domain)
}

// DialWithECH dials the server and performs a secure uTLS handshake with ECH configs enabled.
func DialWithECH(network, addr string, sni string, echConfigList []byte, clientHelloID utls.ClientHelloID) (net.Conn, error) {
	tcpConn, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	config := &utls.Config{
		ServerName: sni,
		NextProtos: []string{"h2", "http/1.1"},
	}

	uConn := utls.UClient(tcpConn, config, clientHelloID)

	if err := uConn.Handshake(); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("uTLS ECH handshake failed: %w", err)
	}

	return uConn, nil
}
