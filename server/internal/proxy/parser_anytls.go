package proxy

import (
	"fmt"
	"net/url"
)

// parseAnyTLS parses a anytls:// URI into a ProxyConfig.
// anytls://password@address:port?sni=example.com&allowInsecure=true&minIdleSessions=5#Remark
func parseAnyTLS(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	password := parsed.User.Username()
	if password == "" && parsed.User != nil {
		password = parsed.User.String()
	}

	port := 443
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}

	q := parsed.Query()
	remark, _ := url.PathUnescape(parsed.Fragment)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	allowInsecure := false
	if q.Get("allowInsecure") == "true" {
		allowInsecure = true
	}

	minIdleSessions := 0
	if val := q.Get("minIdleSessions"); val != "" {
		fmt.Sscanf(val, "%d", &minIdleSessions)
	}

	return &ProxyConfig{
		Protocol:        ProtocolAnyTLS,
		Name:            remark,
		Address:         host,
		Port:            port,
		Password:        password,
		TLS:             true,
		SNI:             q.Get("sni"),
		SkipCertVerify:  allowInsecure,
		MinIdleSessions: minIdleSessions,
	}, nil
}
